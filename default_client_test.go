package wop

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	sdkconfig "github.com/wop-platform/wop-go-sdk/config"
)

func writeDefaultClientConfig(t *testing.T, dir string) string {
	t.Helper()
	priv := loadGoldenVectors(t).Keys.RSA3072.PrivatePkcs8B64
	pub := loadGoldenVectors(t).Keys.RSA3072.PublicSpkiB64
	body := []byte(`{
  "appKey": "app_test_001",
  "suite": "WOP-RSA3072-SHA256",
  "merchantPrivateKey": "` + priv + `",
  "platformPublicKey": "` + pub + `",
  "serverRoot": "https://gw.example.com/gateway"
}`)
	path := filepath.Join(dir, "wopSdkConfig.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultClient_LoadAndReset(t *testing.T) {
	sdkconfig.ClearCache()
	ResetDefault()

	dir := t.TempDir()
	path := writeDefaultClientConfig(t, dir)
	t.Setenv(sdkconfig.EnvConfigFile, path)
	t.Setenv(sdkconfig.EnvConfig, "")

	c1, err := DefaultClient()
	if err != nil {
		t.Fatalf("DefaultClient: %v", err)
	}
	c2, err := DefaultClient()
	if err != nil {
		t.Fatal(err)
	}
	if c1 != c2 {
		t.Fatal("DefaultClient 应缓存同一实例")
	}

	// 轮换：先 ClearCache 再 ResetDefault（K26）
	writeDefaultClientConfig(t, dir) // 同路径内容可不变，测重置流程
	sdkconfig.ClearCache()
	ResetDefault()
	c3, err := DefaultClient()
	if err != nil {
		t.Fatalf("Reset 后 DefaultClient: %v", err)
	}
	if c3 == c1 {
		t.Fatal("Reset 后应构造新实例")
	}
}

func TestDefaultClient_ConcurrentInit(t *testing.T) {
	sdkconfig.ClearCache()
	ResetDefault()

	dir := t.TempDir()
	path := writeDefaultClientConfig(t, dir)
	t.Setenv(sdkconfig.EnvConfigFile, path)

	var wg sync.WaitGroup
	clients := make([]*Client, 8)
	errs := make([]error, 8)
	for i := range clients {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			clients[idx], errs[idx] = DefaultClient()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	first := clients[0]
	for i, c := range clients[1:] {
		if c != first {
			t.Fatalf("并发首调实例不一致: 0 vs %d", i+1)
		}
	}
}

func TestNewFromConfig_Alias(t *testing.T) {
	cfg := testConfig(t, "WOP-RSA3072-SHA256")
	c1, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c1.appKey != c2.appKey || c1.baseURL != c2.baseURL {
		t.Fatal("NewFromConfig 应与 NewClient 等价")
	}
}

func TestNewFromFileConfig(t *testing.T) {
	priv := loadGoldenVectors(t).Keys.RSA3072.PrivatePkcs8B64
	pub := loadGoldenVectors(t).Keys.RSA3072.PublicSpkiB64
	cfg := sdkconfig.Config{
		AppKey:             "app_test_001",
		Suite:              "WOP-RSA3072-SHA256",
		MerchantPrivateKey: priv,
		PlatformPublicKey:  pub,
		ServerRoot:         "https://gw.example.com/gateway",
		ExpiredSeconds:     1800,
		HTTPClient: sdkconfig.HTTPClientConfig{
			ConnectTimeout: 10000,
			ReadTimeout:    30000,
			MaxRetryCount:  3,
		},
	}
	c, err := NewFromFileConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "https://gw.example.com/gateway" {
		t.Fatalf("baseURL=%q", c.baseURL)
	}
}
