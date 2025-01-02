package commands

import (
	b64 "encoding/base64"
	"log"
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	saml2alibabacloud "github.com/aliyun/saml2alibabacloud"
	"github.com/aliyun/saml2alibabacloud/helper/credentials"
	"github.com/aliyun/saml2alibabacloud/pkg/alibabacloudconfig"
	"github.com/aliyun/saml2alibabacloud/pkg/cfg"
	"github.com/aliyun/saml2alibabacloud/pkg/creds"
	"github.com/aliyun/saml2alibabacloud/pkg/flags"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Login login to ADFS
func Login(loginFlags *flags.LoginExecFlags) error {

	logger := logrus.WithField("command", "login")

	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	sharedCreds := alibabacloudconfig.NewSharedCredentials(account.Profile)
    
	logger.Debug("check if Creds Exist")

	// this checks if the credentials file has been created yet
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}
	if !exist {
		log.Println("unable to load credentials, login required to create them")
		return nil
	}

	if !sharedCreds.Expired() && !loginFlags.Force {
		log.Println("credentials are not expired skipping")
		return nil
	}

	loginDetails, err := resolveLoginDetails(account, loginFlags)
	if err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
	}

	err = loginDetails.Validate()
	if err != nil {
		return errors.Wrap(err, "error validating login details")
	}

	logger.WithField("idpAccount", account).Debug("building provider")

	provider, err := saml2alibabacloud.NewSAMLClient(account)
	if err != nil {
		return errors.Wrap(err, "error building IdP client")
	}

	log.Printf("Authenticating as %s ...", loginDetails.Username)

	samlAssertion, err := provider.Authenticate(loginDetails)
	if err != nil {
		return errors.Wrap(err, "error authenticating to IdP")

	}

	if samlAssertion == "" {
		log.Println("Response did not contain a valid SAML assertion")
		log.Println("Please check your username and password is correct")
		log.Println("To see the output follow the instructions in https://github.com/aliyun/saml2alibabacloud#debugging-issues-with-idps")
		os.Exit(1)
	}

	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.SaveCredentials(loginDetails.URL, loginDetails.Username, loginDetails.Password)
		if err != nil {
			return errors.Wrap(err, "error storing password in keychain")
		}
	}

	role, err := selectRamRole(samlAssertion, account)
	if err != nil {
		return errors.Wrap(err, "Failed to assume role, please check whether you are permitted to assume the given role for the AlibabaCloud STS service")
	}

	log.Println("Selected role:", role.RoleARN)

	alibabacloudCreds, err := loginToStsUsingRole(account, role, samlAssertion)
	if err != nil {
		return errors.Wrap(err, "error logging into AlibabaCloud role using saml assertion")
	}

	return saveCredentials(alibabacloudCreds, sharedCreds)
}

func buildIdpAccount(loginFlags *flags.LoginExecFlags) (*cfg.IDPAccount, error) {
	cfgm, err := cfg.NewConfigManager(loginFlags.CommonFlags.ConfigFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load configuration")
	}

	account, err := cfgm.LoadIDPAccount(loginFlags.CommonFlags.IdpAccount)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load idp account")
	}

	// update username and hostname if supplied
	flags.ApplyFlagOverrides(loginFlags.CommonFlags, account)

	err = account.Validate()
	if err != nil {
		return nil, errors.Wrap(err, "failed to validate account")
	}

	return account, nil
}

func resolveLoginDetails(account *cfg.IDPAccount, loginFlags *flags.LoginExecFlags) (*creds.LoginDetails, error) {

	// log.Printf("loginFlags %+v", loginFlags)

	loginDetails := &creds.LoginDetails{URL: account.URL, Username: account.Username, MFAToken: loginFlags.CommonFlags.MFAToken, DuoMFAOption: loginFlags.DuoMFAOption}

	log.Printf("Using IDP Account %s to access %s %s", loginFlags.CommonFlags.IdpAccount, account.Provider, account.URL)

	var err error
	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.LookupCredentials(loginDetails, account.Provider)
		if err != nil {
			if !credentials.IsErrCredentialsNotFound(err) {
				return nil, errors.Wrap(err, "error loading saved password")
			}
		}
	}

	// log.Printf("%s %s", savedUsername, savedPassword)

	// if you supply a username in a flag it takes precedence
	if loginFlags.CommonFlags.Username != "" {
		loginDetails.Username = loginFlags.CommonFlags.Username
	}

	// if you supply a password in a flag it takes precedence
	if loginFlags.CommonFlags.Password != "" {
		loginDetails.Password = loginFlags.CommonFlags.Password
	}

	// if you supply a cleint_id in a flag it takes precedence
	if loginFlags.CommonFlags.ClientID != "" {
		loginDetails.ClientID = loginFlags.CommonFlags.ClientID
	}

	// if you supply a client_secret in a flag it takes precedence
	if loginFlags.CommonFlags.ClientSecret != "" {
		loginDetails.ClientSecret = loginFlags.CommonFlags.ClientSecret
	}

	// log.Printf("loginDetails %+v", loginDetails)

	// if skip prompt was passed just pass back the flag values
	if loginFlags.CommonFlags.SkipPrompt {
		return loginDetails, nil
	}

	err = saml2alibabacloud.PromptForLoginDetails(loginDetails, account.Provider)
	if err != nil {
		return nil, errors.Wrap(err, "Error occurred accepting input")
	}

	return loginDetails, nil
}

func selectRamRole(samlAssertion string, account *cfg.IDPAccount) (*saml2alibabacloud.RamRole, error) {
	data, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding saml assertion")
	}

	roles, err := saml2alibabacloud.ExtractRamRoles(data)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing alicloud roles")
	}

	if len(roles) == 0 {
		log.Println("No roles to assume")
		log.Println("Please check you are permitted to assume roles for the AlibabaCloud service")
		os.Exit(1)
	}

	alibabacloudRoles, err := saml2alibabacloud.ParseRamRoles(roles)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing AlibabaCloud roles")
	}

	return resolveRole(alibabacloudRoles, samlAssertion, account)
}

func resolveRole(alibabacloudRoles []*saml2alibabacloud.RamRole, samlAssertion string, account *cfg.IDPAccount) (*saml2alibabacloud.RamRole, error) {
	var role = new(saml2alibabacloud.RamRole)

	if len(alibabacloudRoles) == 1 {
		if account.RoleARN != "" {
			return saml2alibabacloud.LocateRole(alibabacloudRoles, account.RoleARN)
		}
		return alibabacloudRoles[0], nil
	} else if len(alibabacloudRoles) == 0 {
		return nil, errors.New("no roles available")
	}

	samlAssertionData, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding saml assertion")
	}

	aud, err := saml2alibabacloud.ExtractDestinationURL(samlAssertionData)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing destination url")
	}

	alibabacloudAccounts, err := saml2alibabacloud.ParseAlibabaCloudAccounts(aud, samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing AlibabaCloud role accounts")
	}
	if len(alibabacloudAccounts) == 0 {
		return nil, errors.New("no accounts available")
	}

	// saml2alibabacloud.AssignPrincipals(alibabacloudRoles, alibabacloudAccounts)

	if account.RoleARN != "" {
		return saml2alibabacloud.LocateRole(alibabacloudRoles, account.RoleARN)
	}

	for {
		role, err = saml2alibabacloud.PromptForRamRoleSelection(alibabacloudAccounts)
		if err == nil {
			break
		}
		log.Println("error selecting role, try again")
	}

	return role, nil
}

func loginToStsUsingRole(account *cfg.IDPAccount, role *saml2alibabacloud.RamRole, samlAssertion string) (*alibabacloudconfig.AliCloudCredentials, error) {

	client, err := sts.NewClientWithAccessKey("cn-hangzhou", "saml2alibabacloud", "0.0.6")
	if err != nil {
		return nil, err
	}
	client.AppendUserAgent("saml2alibabacloud", "0.0.6")

	request := sts.CreateAssumeRoleWithSAMLRequest()
	request.Scheme = "https"
	request.RoleArn = role.RoleARN
	request.SAMLAssertion = samlAssertion
	request.SAMLProviderArn = role.PrincipalARN

	log.Println("Requesting AlibabaCloud credentials using SAML assertion")

	response, err := client.AssumeRoleWithSAML(request)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving STS credentials using SAML")
	}

	return &alibabacloudconfig.AliCloudCredentials{
		AliCloudAccessKey:     response.Credentials.AccessKeyId,
		AliCloudSecretKey:     response.Credentials.AccessKeySecret,
		AliCloudSecurityToken: response.Credentials.SecurityToken,
		PrincipalARN:          response.AssumedRoleUser.Arn,
		Region:                account.Region,
	}, nil
}

func saveCredentials(alibabacloudCreds *alibabacloudconfig.AliCloudCredentials, sharedCreds *alibabacloudconfig.CredentialsProvider) error {
	err := sharedCreds.Save(alibabacloudCreds)
	if err != nil {
		return errors.Wrap(err, "error saving credentials")
	}

	log.Println("Logged in as:", alibabacloudCreds.PrincipalARN)
	log.Println("")
	log.Println("Your new access key pair has been stored in the AlibabaCloud CLI configuration")
	// log.Printf("Note that it will expire at %v", alibabacloudCreds.Expires)
	log.Printf("To use this credential, call the AlibabaCloud CLI with the --profile option (e.g. aliyun --profile %s sts GetCallerIdentity --region=%s)", sharedCreds.Profile, alibabacloudCreds.Region)
	log.Println("")
	log.Printf("For your convenience, please execute: alias aliyun='aliyun --profile %s'", sharedCreds.Profile)
	return nil
}
