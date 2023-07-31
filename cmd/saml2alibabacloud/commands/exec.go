package commands

import (
	"fmt"
	"log"

	sdkError "github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/aliyun/saml2alibabacloud/pkg/alibabacloudconfig"
	"github.com/aliyun/saml2alibabacloud/pkg/flags"
	"github.com/aliyun/saml2alibabacloud/pkg/shell"
	"github.com/pkg/errors"
)

// Exec execute the supplied command after seeding the environment
func Exec(execFlags *flags.LoginExecFlags, cmdline []string) error {

	if len(cmdline) < 1 {
		return fmt.Errorf("Command to execute required")
	}

	account, err := buildIdpAccount(execFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	sharedCreds := alibabacloudconfig.NewSharedCredentials(account.Profile)

	// this checks if the credentials file has been created yet
	// can only really be triggered if saml2alibabacloud exec is run on a new
	// system prior to creating $HOME/.aliyun
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}
	if !exist {
		log.Println("unable to load credentials, login required to create them")
		return nil
	}

	alibabacloudCreds, err := sharedCreds.Load()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}

	ok, err := checkToken(alibabacloudCreds)
	if err != nil {
		return errors.Wrap(err, "error validating token")
	}

	if !ok {
		err = Login(execFlags)
	}
	if err != nil {
		return errors.Wrap(err, "error logging in")
	}

	if execFlags.ExecProfile != "" {
		// Assume the desired role before generating env vars
		alibabacloudCreds, err = assumeRoleWithProfile(alibabacloudCreds, execFlags.ExecProfile, execFlags.CommonFlags.SessionDuration)
		if err != nil {
			return errors.Wrap(err,
				fmt.Sprintf("error acquiring credentials for profile: %s", execFlags.ExecProfile))
		}
	}

	return shell.ExecShellCmd(cmdline, shell.BuildEnvVars(alibabacloudCreds, account, execFlags))
}

// assumeRoleWithProfile uses an AlibabaCloud CLI profile (via ~/.aliyun/config.json) and performs (multiple levels of) role assumption
// This is extremely useful in the case of a central "authentication account" which then requires secondary, and
// often tertiary, role assumptions to acquire credentials for the target role.
func assumeRoleWithProfile(alibabacloudCreds *alibabacloudconfig.AliCloudCredentials, targetProfile string, sessionDuration int) (*alibabacloudconfig.AliCloudCredentials, error) {

	// get target profile
	sharedCreds := alibabacloudconfig.NewSharedCredentials(targetProfile)

	// this checks if the credentials file has been created yet
	// can only really be triggered if saml2alibabacloud exec is run on a new
	// system prior to creating $HOME/.aliyun
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return nil, errors.Wrap(err, "error loading target credentials")
	}
	if !exist {
		log.Println("unable to load target credentials")
		return nil, errors.New("unable to load target credentials")
	}

	targetCreds, err := sharedCreds.Load()
	if err != nil {
		return nil, errors.Wrap(err, "error loading target credentials")
	}

	// AlibabaCloud session config with verbose errors on chained credential errors
	client, err := sts.NewClientWithStsToken("cn-hangzhou", alibabacloudCreds.AliCloudAccessKey, alibabacloudCreds.AliCloudSecretKey, alibabacloudCreds.AliCloudSecurityToken)
	if err != nil {
		return nil, err
	}
	client.AppendUserAgent("saml2alibabacloud", "0.0.6")
	request := sts.CreateAssumeRoleRequest()
	request.RoleSessionName = targetCreds.AliCloudSessionToken
	request.RoleArn = targetCreds.PrincipalARN
	request.DurationSeconds = requests.NewInteger(sessionDuration)

	// use an STS client to perform the multiple role assumptions
	response, err := client.AssumeRole(request)
	if err != nil {
		return nil, err
	}

	return &alibabacloudconfig.AliCloudCredentials{
		AliCloudAccessKey:     response.Credentials.AccessKeyId,
		AliCloudSecretKey:     response.Credentials.AccessKeySecret,
		AliCloudSessionToken:  targetCreds.AliCloudSessionToken,
		AliCloudSecurityToken: response.Credentials.SecurityToken,
		PrincipalARN:          response.AssumedRoleUser.Arn,
	}, nil
}

func checkToken(alibabacloudCreds *alibabacloudconfig.AliCloudCredentials) (bool, error) {
	client, err := sts.NewClientWithStsToken("cn-hangzhou", alibabacloudCreds.AliCloudAccessKey, alibabacloudCreds.AliCloudSecretKey, alibabacloudCreds.AliCloudSecurityToken)

	if err != nil {
		return false, err
	}

	client.AppendUserAgent("saml2alibabacloud", "0.0.6")

	request := sts.CreateGetCallerIdentityRequest()

	_, err = client.GetCallerIdentity(request)
	if err != nil {
		if serverErr, ok := err.(*sdkError.ServerError); ok {
			if serverErr.ErrorCode() == "InvalidSecurityToken.Expired" {
				return false, nil
			}
		}

		return false, err
	}

	return true, nil
}
