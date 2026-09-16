package config

import _ "embed"

const embeddedConfigPath = "__embedded__/config/wopSdkConfig.json"

//go:embed wopSdkConfig.json
var embeddedDefaultConfig []byte
