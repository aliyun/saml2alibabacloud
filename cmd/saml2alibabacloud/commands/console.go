package commands

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/aliyun/saml2alibabacloud/pkg/alibabacloudconfig"
	"github.com/aliyun/saml2alibabacloud/pkg/cfg"
	"github.com/aliyun/saml2alibabacloud/pkg/flags"
	"github.com/pkg/errors"
	"github.com/skratchdot/open-golang/open"
)

const (
	federationURL = "https://signin.aliyun.com/federation"
	issuer        = "saml2alibabacloud"
)

// Console open the AlibabaCloud console from the CLI
func Console(consoleFlags *flags.ConsoleFlags) error {

	account, err := buildIdpAccount(consoleFlags.LoginExecFlags)
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

	alibabacloudCreds, err := loadOrLogin(account, sharedCreds, consoleFlags)
	if err != nil {
		return errors.Wrap(err,
			fmt.Sprintf("error loading credentials for profile: %s", consoleFlags.LoginExecFlags.ExecProfile))
	}
	if err != nil {
		return errors.Wrap(err, "error logging in")
	}

	if consoleFlags.LoginExecFlags.ExecProfile != "" {
		// Assume the desired role before generating env vars
		alibabacloudCreds, err = assumeRoleWithProfile(alibabacloudCreds, account, consoleFlags.LoginExecFlags.ExecProfile, consoleFlags.LoginExecFlags.CommonFlags.SessionDuration)
		if err != nil {
			return errors.Wrap(err,
				fmt.Sprintf("error acquiring credentials for profile: %s", consoleFlags.LoginExecFlags.ExecProfile))
		}
	}

	log.Printf("Presenting credentials for %s to %s", account.Profile, federationURL)
	return federatedLogin(alibabacloudCreds, consoleFlags)
}

func loadOrLogin(account *cfg.IDPAccount, sharedCreds *alibabacloudconfig.CredentialsProvider, execFlags *flags.ConsoleFlags) (*alibabacloudconfig.AliCloudCredentials, error) {

	var err error

	if execFlags.LoginExecFlags.Force {
		log.Println("force login requested")
		return loginRefreshCredentials(sharedCreds, execFlags.LoginExecFlags)
	}

	alibabacloudCreds, err := sharedCreds.Load()
	if err != nil {
		if err != alibabacloudconfig.ErrCredentialsNotFound {
			return nil, errors.Wrap(err, "failed to load credentials")
		}
		log.Println("credentials not found triggering login")
		return loginRefreshCredentials(sharedCreds, execFlags.LoginExecFlags)
	}

	ok, err := checkToken(alibabacloudCreds, account)
	if err != nil {
		return nil, errors.Wrap(err, "error validating token")
	}

	if !ok {
		log.Println("AlibabaCloud rejected credentials triggering login")
		return loginRefreshCredentials(sharedCreds, execFlags.LoginExecFlags)
	}

	return alibabacloudCreds, nil
}

func loginRefreshCredentials(sharedCreds *alibabacloudconfig.CredentialsProvider, execFlags *flags.LoginExecFlags) (*alibabacloudconfig.AliCloudCredentials, error) {
	err := Login(execFlags)
	if err != nil {
		return nil, errors.Wrap(err, "error logging in")
	}

	return sharedCreds.Load()
}

func federatedLogin(creds *alibabacloudconfig.AliCloudCredentials, consoleFlags *flags.ConsoleFlags) error {
	jsonBytes, err := json.Marshal(map[string]string{
		"sessionId":    creds.AliCloudAccessKey,
		"sessionKey":   creds.AliCloudSecretKey,
		"sessionToken": creds.AliCloudSessionToken,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("GET", federationURL, nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonBytes))

	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Call to getSigninToken failed with %v", resp.Status)
	}

	var respParsed map[string]string
	if err = json.Unmarshal([]byte(body), &respParsed); err != nil {
		return err
	}

	signinToken, ok := respParsed["SigninToken"]
	if !ok {
		return err
	}

	destination := "https://home.console.aliyun.com/"

	loginURL := fmt.Sprintf(
		"%s?Action=login&Issuer=%s&Destination=%s&SigninToken=%s",
		federationURL,
		issuer,
		url.QueryEscape(destination),
		url.QueryEscape(signinToken),
	)

	// write the URL to stdout making it easy to capture seperately and use in a shell function
	if consoleFlags.Link {
		fmt.Println(loginURL)
		return nil
	}

	return open.Run(loginURL)
}
