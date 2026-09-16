package config

// Config 是不可变配置快照（与 JSON camelCase 字段一一对应）。
type Config struct {
	AppKey             string
	Suite              string
	MerchantPrivateKey string
	PlatformPublicKey  string
	ServerRoot         string
	BackupServerRoots  []string
	ExpiredSeconds     int64
	HTTPClient         HTTPClientConfig
}

// HTTPClientConfig 全局 HTTP 客户端参数（毫秒/次数）。
type HTTPClientConfig struct {
	ConnectTimeout int
	ReadTimeout    int
	MaxRetryCount  int
}
