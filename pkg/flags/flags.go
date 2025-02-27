package flags

import (
	"github.com/aliyun/saml2alibabacloud/pkg/cfg"
)

// CommonFlags flags common to all of the `saml2alibabacloud` commands (except `help`)
type CommonFlags struct {
	AppID                 string
	BrowserType           string
	BrowserExecutablePath string
	BrowserAutoFill       bool
	ClientID              string
	ClientSecret          string
	ConfigFile            string
	IdpAccount            string
	IdpProvider           string
	MFA                   string
	MFAToken              string
	URL                   string
	Username              string
	Password              string
	RoleArn               string
	AlibabaCloudURN       string
	SessionDuration       int
	SkipPrompt            bool
	SkipVerify            bool
	Profile               string
	Subdomain             string
	ResourceID            string
	DisableKeychain       bool
	Region                string
}

// LoginExecFlags flags for the Login / Exec commands
type LoginExecFlags struct {
	CommonFlags     *CommonFlags
	DownloadBrowser bool
	Force           bool
	DuoMFAOption    string
	ExecProfile     string
}

type ConsoleFlags struct {
	LoginExecFlags *LoginExecFlags
	Link           bool
}

// ApplyFlagOverrides overrides IDPAccount with command line settings
func ApplyFlagOverrides(commonFlags *CommonFlags, account *cfg.IDPAccount) {
	if commonFlags.AppID != "" {
		account.AppID = commonFlags.AppID
	}

	if commonFlags.URL != "" {
		account.URL = commonFlags.URL
	}

	if commonFlags.Username != "" {
		account.Username = commonFlags.Username
	}

	if commonFlags.SkipVerify {
		account.SkipVerify = commonFlags.SkipVerify
	}

	if commonFlags.IdpProvider != "" {
		account.Provider = commonFlags.IdpProvider
	}

	if commonFlags.BrowserType != "" {
		account.BrowserType = commonFlags.BrowserType
	}

	if commonFlags.MFA != "" {
		account.MFA = commonFlags.MFA
	}

	if commonFlags.AlibabaCloudURN != "" {
		account.AlibabaCloudURN = commonFlags.AlibabaCloudURN
	}

	if commonFlags.SessionDuration != 0 {
		account.SessionDuration = commonFlags.SessionDuration
	}

	if commonFlags.Profile != "" {
		account.Profile = commonFlags.Profile
	}

	if commonFlags.Subdomain != "" {
		account.Subdomain = commonFlags.Subdomain
	}

	if commonFlags.RoleArn != "" {
		account.RoleARN = commonFlags.RoleArn
	}
	if commonFlags.ResourceID != "" {
		account.ResourceID = commonFlags.ResourceID
	}
	if commonFlags.Region != "" {
		account.Region = commonFlags.Region
	}
}
