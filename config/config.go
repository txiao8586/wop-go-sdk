package config

// Config 是不可变配置快照（与 JSON camelCase 字段一一对应）。
type Config struct {
	AppKey             string
	Suite              string
	MerchantPrivateKey string
	PlatformPublicKey  string
	ServerRoot         string
	// BackupServerRoots 备用网关根地址（有序，仅全局）。字段按 config-spec §3.3 解析与校验，
	// 但故障转移（Failover）属 P2 阶段（config-spec §7.3 / 附录 B）：当前版本候选仅 ServerRoot，
	// 本字段暂不改变请求行为——K9 能力边界诚实披露。
	BackupServerRoots []string
	ExpiredSeconds    int64
	HTTPClient        HTTPClientConfig
}

// HTTPClientConfig 全局 HTTP 客户端参数（毫秒/次数）。
type HTTPClientConfig struct {
	ConnectTimeout int
	ReadTimeout    int
	// MaxRetryCount 跨域名重试上限。按 config-spec §3.3 解析，随 Failover（P2）生效；
	// 当前版本无重试语义，暂不改变请求行为——K9 能力边界诚实披露。
	MaxRetryCount int
}
