package wop

import (
	"errors"
	"sync"

	sdkconfig "github.com/wop-platform/wop-go-sdk/config"
)

// defaultHolder 默认客户端单例持有者（K15：mutex 全路径保护）。
var defaultHolder defaultClientHolder

// defaultClientHolder 持有默认实例与初始化错误（K26：Reset 双清零）。
type defaultClientHolder struct {
	mu      sync.Mutex
	client  *Client
	initErr error
}

// DefaultClient 惰性加载默认配置并构造客户端（§5 K15/K17）。
func DefaultClient() (*Client, error) {
	defaultHolder.mu.Lock()
	defer defaultHolder.mu.Unlock()
	if defaultHolder.client != nil {
		return defaultHolder.client, defaultHolder.initErr
	}
	if defaultHolder.initErr != nil {
		return nil, defaultHolder.initErr
	}
	cfg, err := sdkconfig.LoadDefault()
	if err != nil {
		defaultHolder.initErr = wrapConfigError(err)
		return nil, defaultHolder.initErr
	}
	defaultHolder.client, defaultHolder.initErr = NewFromFileConfig(cfg)
	return defaultHolder.client, defaultHolder.initErr
}

// ResetDefault 丢弃默认实例与初始化状态；须先 config.ClearCache()（§5 K26）。
func ResetDefault() {
	defaultHolder.mu.Lock()
	defer defaultHolder.mu.Unlock()
	defaultHolder.client = nil
	defaultHolder.initErr = nil
}

// NewFromConfig 由程序化 Config 构造客户端（§2.1 K11，等价 NewClient）。
func NewFromConfig(cfg Config) (*Client, error) {
	return NewClient(cfg)
}

// NewFromFileConfig 由 config 包加载快照构造客户端（含密钥解析校验）。
func NewFromFileConfig(cfg sdkconfig.Config) (*Client, error) {
	wopCfg := Config{
		AppKey:             cfg.AppKey,
		SecurityReq:        cfg.Suite,
		MerchantPrivateKey: cfg.MerchantPrivateKey,
		PlatformPublicKey:  cfg.PlatformPublicKey,
		ServerRoot:         cfg.ServerRoot,
		GatewayBaseURL:     cfg.ServerRoot,
		BackupServerRoots:  append([]string(nil), cfg.BackupServerRoots...),
		ExpiredSeconds:     cfg.ExpiredSeconds,
		HTTPClient: HTTPClientSettings{
			ConnectTimeout: cfg.HTTPClient.ConnectTimeout,
			ReadTimeout:    cfg.HTTPClient.ReadTimeout,
			MaxRetryCount:  cfg.HTTPClient.MaxRetryCount,
		},
	}
	return NewClient(wopCfg)
}

// wrapConfigError 将 config 包错误映射为 wop configuration 错误。
func wrapConfigError(err error) error {
	var ce *sdkconfig.Error
	if errors.As(err, &ce) {
		return newError(CodeConfiguration, "%s", ce.Message)
	}
	return newError(CodeConfiguration, "配置加载失败: %v", err)
}
