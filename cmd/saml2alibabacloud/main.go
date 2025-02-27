package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/alecthomas/kingpin"
	"github.com/aliyun/saml2alibabacloud/cmd/saml2alibabacloud/commands"
	"github.com/aliyun/saml2alibabacloud/pkg/flags"
	"github.com/sirupsen/logrus"
)

var (
	// Version app version
	Version = "0.0.8"
)

// The `cmdLineList` type is used to make a `[]string` meet the requirements
// of the kingpin.Value interface
type cmdLineList []string

func (i *cmdLineList) Set(value string) error {
	*i = append(*i, value)

	return nil
}

func (i *cmdLineList) String() string {
	return ""
}

func (i *cmdLineList) IsCumulative() bool {
	return true
}

func buildCmdList(s kingpin.Settings) (target *[]string) {
	target = new([]string)
	s.SetValue((*cmdLineList)(target))
	return
}

func main() {

	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	logrus.SetOutput(os.Stderr)

	// the following avoids issues with powershell, and shells in windows reporting a program errors
	// because it has written to stderr
	if runtime.GOOS == "windows" {
		log.SetOutput(os.Stdout)
		logrus.SetOutput(os.Stdout)
	}

	app := kingpin.New("saml2alibabacloud", "A command line tool to help with SAML access to the AlibabaCloud STS service.")
	app.Version(Version)

	// Settings not related to commands
	verbose := app.Flag("verbose", "Enable verbose logging").Bool()
	provider := app.Flag("provider", "This flag is obsolete. See: https://github.com/aliyun/saml2alibabacloud#configuring-idp-accounts").Short('i').Enum("Akamai", "AzureAD", "ADFS", "ADFS2", "Ping", "JumpCloud", "Okta", "OneLogin", "PSU", "KeyCloak", "Browser")

	// Common (to all commands) settings
	commonFlags := new(flags.CommonFlags)
	app.Flag("config", "Path/filename of saml2alibabacloud config file (env: SAML2ALIBABACLOUD_CONFIGFILE)").Envar("SAML2ALIBABACLOUD_CONFIGFILE").StringVar(&commonFlags.ConfigFile)
	app.Flag("idp-account", "The name of the configured IDP account. (env: SAML2ALIBABACLOUD_IDP_ACCOUNT)").Envar("SAML2ALIBABACLOUD_IDP_ACCOUNT").Short('a').Default("default").StringVar(&commonFlags.IdpAccount)
	app.Flag("idp-provider", "The configured IDP provider. (env: SAML2ALIBABACLOUD_IDP_PROVIDER)").Envar("SAML2ALIBABACLOUD_IDP_PROVIDER").EnumVar(&commonFlags.IdpProvider, "Akamai", "AzureAD", "ADFS", "ADFS2", "GoogleApps", "Ping", "JumpCloud", "Okta", "OneLogin", "PSU", "KeyCloak", "F5APM", "Shibboleth", "ShibbolethECP", "NetIQ")
	app.Flag("mfa", "The name of the mfa. (env: SAML2ALIBABACLOUD_MFA)").Envar("SAML2ALIBABACLOUD_MFA").StringVar(&commonFlags.MFA)
	app.Flag("skip-verify", "Skip verification of server certificate. (env: SAML2ALIBABACLOUD_SKIP_VERIFY)").Envar("SAML2ALIBABACLOUD_SKIP_VERIFY").Short('s').BoolVar(&commonFlags.SkipVerify)
	app.Flag("url", "The URL of the SAML IDP server used to login. (env: SAML2ALIBABACLOUD_URL)").Envar("SAML2ALIBABACLOUD_URL").StringVar(&commonFlags.URL)
	app.Flag("username", "The username used to login. (env: SAML2ALIBABACLOUD_USERNAME)").Envar("SAML2ALIBABACLOUD_USERNAME").StringVar(&commonFlags.Username)
	app.Flag("password", "The password used to login. (env: SAML2ALIBABACLOUD_PASSWORD)").Envar("SAML2ALIBABACLOUD_PASSWORD").StringVar(&commonFlags.Password)
	app.Flag("mfa-token", "The current MFA token (supported in Keycloak, ADFS, GoogleApps). (env: SAML2ALIBABACLOUD_MFA_TOKEN)").Envar("SAML2ALIBABACLOUD_MFA_TOKEN").StringVar(&commonFlags.MFAToken)
	app.Flag("role", "The ARN of the role to assume. (env: SAML2ALIBABACLOUD_ROLE)").Envar("SAML2ALIBABACLOUD_ROLE").StringVar(&commonFlags.RoleArn)
	app.Flag("urn", "The URN used by SAML when you login. (env: SAML2ALIBABACLOUD_URN)").Envar("SAML2ALIBABACLOUD_URN").StringVar(&commonFlags.AlibabaCloudURN)
	app.Flag("skip-prompt", "Skip prompting for parameters during login.").BoolVar(&commonFlags.SkipPrompt)
	app.Flag("session-duration", "The duration of your AlibabaCloud Session. (env: SAML2ALIBABACLOUD_SESSION_DURATION)").Envar("SAML2ALIBABACLOUD_SESSION_DURATION").IntVar(&commonFlags.SessionDuration)
	app.Flag("disable-keychain", "Do not use keychain at all.").Envar("SAML2ALIBABACLOUD_DISABLE_KEYCHAIN").BoolVar(&commonFlags.DisableKeychain)
	app.Flag("region", "AlibabaCloud region to use for API requests, e.g. cn-hangzhou, ap-southeast-1 (env: SAML2ALIBABACLOUD_REGION)").Envar("SAML2ALIBABACLOUD_REGION").Short('r').StringVar(&commonFlags.Region)
	app.Flag("browser-type", "The configured browser type when the IDP provider is set to Browser. if not set 'chromium' will be used. (env: SAML2ALIBABACLOUD_BROWSER_TYPE)").Envar("SAML2ALIBABACLOUD_BROWSER_TYPE").EnumVar(&commonFlags.BrowserType, "chromium", "firefox", "webkit", "chrome", "chrome-beta", "chrome-dev", "chrome-canary", "msedge", "msedge-beta", "msedge-dev", "msedge-canary")
	app.Flag("browser-executable-path", "The configured browser full path when the IDP provider is set to Browser. If set, no browser download will be performed and the executable path will be used instead. (env: SAML2ALIBABACLOUD_BROWSER_EXECUTABLE_PATH)").Envar("SAML2ALIBABACLOUD_BROWSER_EXECUTABLE_PATH").StringVar(&commonFlags.BrowserExecutablePath)
	app.Flag("browser-autofill", "Configures browser to autofill the username and password. (env: SAML2ALIBABACLOUD_BROWSER_AUTOFILL)").Envar("SAML2ALIBABACLOUD_BROWSER_AUTOFILL").BoolVar(&commonFlags.BrowserAutoFill)

	// `configure` command and settings
	cmdConfigure := app.Command("configure", "Configure a new IDP account.")
	cmdConfigure.Flag("app-id", "OneLogin app id required for SAML assertion. (env: ONELOGIN_APP_ID)").Envar("ONELOGIN_APP_ID").StringVar(&commonFlags.AppID)
	cmdConfigure.Flag("client-id", "OneLogin client id, used to generate API access token. (env: ONELOGIN_CLIENT_ID)").Envar("ONELOGIN_CLIENT_ID").StringVar(&commonFlags.ClientID)
	cmdConfigure.Flag("client-secret", "OneLogin client secret, used to generate API access token. (env: ONELOGIN_CLIENT_SECRET)").Envar("ONELOGIN_CLIENT_SECRET").StringVar(&commonFlags.ClientSecret)
	cmdConfigure.Flag("subdomain", "OneLogin subdomain of your company account. (env: ONELOGIN_SUBDOMAIN)").Envar("ONELOGIN_SUBDOMAIN").StringVar(&commonFlags.Subdomain)
	cmdConfigure.Flag("profile", "The AlibabaCloud CLI profile to save the temporary credentials. (env: SAML2ALIBABACLOUD_PROFILE)").Envar("SAML2ALIBABACLOUD_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	cmdConfigure.Flag("resource-id", "F5APM SAML resource ID of your company account. (env: SAML2ALIBABACLOUD_F5APM_RESOURCE_ID)").Envar("SAML2ALIBABACLOUD_F5APM_RESOURCE_ID").StringVar(&commonFlags.ResourceID)
	configFlags := commonFlags

	// `login` command and settings
	cmdLogin := app.Command("login", "Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.")
	loginFlags := new(flags.LoginExecFlags)
	loginFlags.CommonFlags = commonFlags
	cmdLogin.Flag("profile", "The AlibabaCloud CLI profile to save the temporary credentials. (env: SAML2ALIBABACLOUD_PROFILE)").Short('p').Envar("SAML2ALIBABACLOUD_PROFILE").StringVar(&commonFlags.Profile)
	cmdLogin.Flag("duo-mfa-option", "The MFA option you want to use to authenticate with").Envar("SAML2ALIBABACLOUD_DUO_MFA_OPTION").EnumVar(&loginFlags.DuoMFAOption, "Passcode", "Duo Push")
	cmdLogin.Flag("client-id", "OneLogin client id, used to generate API access token. (env: ONELOGIN_CLIENT_ID)").Envar("ONELOGIN_CLIENT_ID").StringVar(&commonFlags.ClientID)
	cmdLogin.Flag("client-secret", "OneLogin client secret, used to generate API access token. (env: ONELOGIN_CLIENT_SECRET)").Envar("ONELOGIN_CLIENT_SECRET").StringVar(&commonFlags.ClientSecret)
	cmdLogin.Flag("force", "Refresh credentials even if not expired.").BoolVar(&loginFlags.Force)
	cmdLogin.Flag("download-browser-driver", "Automatically download browsers for Browser IDP. (env: SAML2ALIBABACLOUD_AUTO_BROWSER_DOWNLOAD)").Envar("SAML2ALIBABACLOUD_AUTO_BROWSER_DOWNLOAD").BoolVar(&loginFlags.DownloadBrowser)

	// `exec` command and settings
	cmdExec := app.Command("exec", "Exec the supplied command with env vars from STS token.")
	execFlags := new(flags.LoginExecFlags)
	execFlags.CommonFlags = commonFlags
	cmdExec.Flag("profile", "The AlibabaCloud CLI profile to save the temporary credentials. (env: SAML2ALIBABACLOUD_PROFILE)").Envar("SAML2ALIBABACLOUD_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	cmdExec.Flag("exec-profile", "The AlibabaCloud CLI profile to utilize for command execution. Useful to allow the `aliyun` cli to perform secondary role assumption. (env: SAML2ALIBABACLOUD_EXEC_PROFILE)").Envar("SAML2ALIBABACLOUD_EXEC_PROFILE").StringVar(&execFlags.ExecProfile)
	cmdLine := buildCmdList(cmdExec.Arg("command", "The command to execute."))

	// `console` command and settings
	cmdConsole := app.Command("console", "Console will open the AlibabaCloud console after logging in.")
	consoleFlags := new(flags.ConsoleFlags)
	consoleFlags.LoginExecFlags = execFlags
	consoleFlags.LoginExecFlags.CommonFlags = commonFlags
	cmdConsole.Flag("exec-profile", "The AlibabaCloud CLI profile to utilize for console execution. (env: SAML2ALIBABACLOUD_EXEC_PROFILE)").Envar("SAML2ALIBABACLOUD_EXEC_PROFILE").StringVar(&consoleFlags.LoginExecFlags.ExecProfile)
	cmdConsole.Flag("profile", "The AlibabaCloud CLI profile to save the temporary credentials. (env: SAML2ALIBABACLOUD_PROFILE)").Envar("SAML2ALIBABACLOUD_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	cmdConsole.Flag("force", "Refresh credentials even if not expired.").BoolVar(&consoleFlags.LoginExecFlags.Force)
	cmdConsole.Flag("link", "Present link to AlibabaCloud console instead of opening browser").BoolVar(&consoleFlags.Link)

	// `list` command and settings
	cmdListRoles := app.Command("list-roles", "List available role ARNs.")
	listRolesFlags := new(flags.LoginExecFlags)
	listRolesFlags.CommonFlags = commonFlags

	// `script` command and settings
	cmdScript := app.Command("script", "Emit a script that will export environment variables.")
	scriptFlags := new(flags.LoginExecFlags)
	scriptFlags.CommonFlags = commonFlags
	cmdScript.Flag("profile", "The AlibabaCloud CLI profile to save the temporary credentials. (env: SAML2ALIBABACLOUD_PROFILE)").Envar("SAML2ALIBABACLOUD_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	var shell string
	cmdScript.
		Flag("shell", "Type of shell environment. Options include: bash, powershell, fish").
		Default("bash").
		EnumVar(&shell, "bash", "powershell", "fish")

	// Trigger the parsing of the command line inputs via kingpin
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	// will leave this here for a while during upgrade process
	if *provider != "" {
		log.Println("The --provider flag has been replaced with a new configure command. See https://github.com/aliyun/saml2alibabacloud#adding-idp-accounts")
		os.Exit(1)
	}

	errtpl := "%v\n"
	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
		errtpl = "%+v\n"
	}

	// Set the default transport settings so all http clients will pick them up.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: commonFlags.SkipVerify}
	http.DefaultTransport.(*http.Transport).Proxy = http.ProxyFromEnvironment

	logrus.WithField("command", command).Debug("Running")

	var err error
	switch command {
	case cmdScript.FullCommand():
		err = commands.Script(scriptFlags, shell)
	case cmdLogin.FullCommand():
		err = commands.Login(loginFlags)
	case cmdExec.FullCommand():
		err = commands.Exec(execFlags, *cmdLine)
	case cmdConsole.FullCommand():
		err = commands.Console(consoleFlags)
	case cmdListRoles.FullCommand():
		err = commands.ListRoles(listRolesFlags)
	case cmdConfigure.FullCommand():
		err = commands.Configure(configFlags)
	}

	if err != nil {
		log.Printf(errtpl, err)
		os.Exit(1)
	}
}
