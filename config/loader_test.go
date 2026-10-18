package config

import (
	"encoding/json"
	"github.com/wop-platform/wop-go-sdk/internal/testvectors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testKeyMaterial(t *testing.T) (merchantPriv, platformPub string) {
	t.Helper()
	raw, err := os.ReadFile(testvectors.Path("crypto-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Keys struct {
			RSA3072 struct {
				PublicSpkiB64   string `json:"publicSpkiB64"`
				PrivatePkcs8B64 string `json:"privatePkcs8B64"`
			} `json:"rsa3072"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v.Keys.RSA3072.PrivatePkcs8B64, v.Keys.RSA3072.PublicSpkiB64
}

func writeValidConfig(t *testing.T, dir string, mutate func(map[string]any)) string {
	t.Helper()
	priv, pub := testKeyMaterial(t)
	doc := map[string]any{
		"appKey":             "app_test_001",
		"suite":              "WOP-RSA3072-SHA256",
		"merchantPrivateKey": priv,
		"platformPublicKey":  pub,
		"serverRoot":         "https://gw.example.com/gateway",
		"backupServerRoots":  []string{"https://gw-backup.example.com/gateway"},
		"expiredSeconds":     1800,
		"httpClient": map[string]any{
			"connectTimeout": 10000,
			"readTimeout":    30000,
			"maxRetryCount":  3,
		},
	}
	if mutate != nil {
		mutate(doc)
	}
	path := filepath.Join(dir, "wopSdkConfig.json")
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_ValidConfig(t *testing.T) {
	ClearCache()
	dir := t.TempDir()
	path := writeValidConfig(t, dir, nil)

	cfg1, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg1, cfg2) {
		t.Fatal("缓存命中应返回等价 Config")
	}
	if cfg1.AppKey != "app_test_001" || cfg1.ServerRoot != "https://gw.example.com/gateway" {
		t.Fatalf("字段映射错误: %+v", cfg1)
	}
	if cfg1.HTTPClient.ConnectTimeout != 10000 || cfg1.HTTPClient.MaxRetryCount != 3 {
		t.Fatalf("httpClient 默认值错误: %+v", cfg1.HTTPClient)
	}
}

func TestLoad_ValidationErrors(t *testing.T) {
	dir := t.TempDir()
	priv, pub := testKeyMaterial(t)
	base := map[string]any{
		"appKey":             "app_test_001",
		"suite":              "WOP-RSA3072-SHA256",
		"merchantPrivateKey": priv,
		"platformPublicKey":  pub,
		"serverRoot":         "https://gw.example.com/gateway",
	}
	cases := []struct {
		name    string
		doc     map[string]any
		rawJSON string
		wantSub string
	}{
		{
			name: "缺少 appKey",
			doc: func() map[string]any {
				c := copyMap(base)
				delete(c, "appKey")
				return c
			}(),
			wantSub: "缺少必填项: appKey",
		},
		{
			name:    "重复 appKey",
			rawJSON: `{"appKey":"a","appKey":"b","suite":"WOP-RSA3072-SHA256","merchantPrivateKey":"k","platformPublicKey":"k","serverRoot":"https://gw.example.com/gateway"}`,
			wantSub: "配置字段 appKey 重复",
		},
		{
			name: "http 网关",
			doc: func() map[string]any {
				c := copyMap(base)
				c["serverRoot"] = "http://gw.example.com/gateway"
				return c
			}(),
			wantSub: "serverRoot 须为 HTTPS 绝对 URL",
		},
		{
			name: "serverRoot 含 query",
			doc: func() map[string]any {
				c := copyMap(base)
				c["serverRoot"] = "https://gw.example.com/gateway?x=1"
				return c
			}(),
			wantSub: "serverRoot 不得含 query 或 fragment",
		},
		{
			name: "backup 含 fragment",
			doc: func() map[string]any {
				c := copyMap(base)
				c["backupServerRoots"] = []string{"https://gw-backup.example.com/gateway#x"}
				return c
			}(),
			wantSub: "backupServerRoots[1] 不得含 query 或 fragment",
		},
		{
			name: "非法 suite",
			doc: func() map[string]any {
				c := copyMap(base)
				c["suite"] = "WOP-UNKNOWN-SHA256"
				return c
			}(),
			wantSub: "不支持的算法套件",
		},
		{
			name: "expiredSeconds 非正",
			doc: func() map[string]any {
				c := copyMap(base)
				c["expiredSeconds"] = 0
				return c
			}(),
			wantSub: "expiredSeconds 须为正整数",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ClearCache()
			path := filepath.Join(dir, tc.name+".json")
			var b []byte
			var err error
			if tc.rawJSON != "" {
				b = []byte(tc.rawJSON)
			} else {
				b, err = json.Marshal(tc.doc)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = Load(path)
			if err == nil {
				t.Fatal("应失败")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err=%q want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestLoadDefault_DiscoveryOrder(t *testing.T) {
	ClearCache()
	t.Setenv(EnvConfigFile, "")
	t.Setenv(EnvConfig, "")

	dir := t.TempDir()
	path := writeValidConfig(t, dir, nil)
	t.Setenv(EnvConfigFile, path)

	cfg, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	if cfg.AppKey != "app_test_001" {
		t.Fatalf("cfg=%+v", cfg)
	}
}

func TestLoadDefault_ExplicitUnreadable(t *testing.T) {
	ClearCache()
	t.Setenv(EnvConfigFile, filepath.Join(t.TempDir(), "missing.json"))
	_, err := LoadDefault()
	if err == nil || !strings.Contains(err.Error(), "配置文件不可读") {
		t.Fatalf("err=%v", err)
	}
}

func copyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
