package commands

import (
	"os"

	"github.com/aliyun/saml2alibabacloud/helper/credentials"
	"github.com/aliyun/saml2alibabacloud/helper/linuxkeyring"
	"github.com/aliyun/saml2alibabacloud/pkg/cfg"
)

func init() {
	c := linuxkeyring.Configuration{
		Backend: os.Getenv(cfg.KeyringBackEnvironmentVariableName),
	}

	if keyringHelper, err := linuxkeyring.NewKeyringHelper(c); err == nil {
		credentials.CurrentHelper = keyringHelper
	}
}
