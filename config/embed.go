package config

import _ "embed"

// embeddedConfigPath 打包资源路径占位（兜底来源标识，K6：外部配置优先）。
const embeddedConfigPath = "__embedded__/config/wopSdkConfig.json"

//go:embed wopSdkConfig.json
var embeddedDefaultConfig []byte
