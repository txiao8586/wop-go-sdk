package config

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/url"
	"strings"
)

const (
	defaultConnectTimeout = 10000
	defaultReadTimeout    = 30000
	defaultMaxRetryCount  = 3
	defaultExpiredSeconds = int64(1800)
)

var validSuites = map[string]struct{}{
	"WOP-RSA3072-SHA256": {},
	"WOP-RSA4096-SHA256": {},
	"WOP-SM2-SM3":        {},
}

type rawConfig struct {
	AppKey             string           `json:"appKey"`
	Suite              string           `json:"suite"`
	MerchantPrivateKey string           `json:"merchantPrivateKey"`
	PlatformPublicKey  string           `json:"platformPublicKey"`
	ServerRoot         string           `json:"serverRoot"`
	BackupServerRoots  []string         `json:"backupServerRoots"`
	ExpiredSeconds     *json.Number     `json:"expiredSeconds"`
	HTTPClient         *rawHTTPClient   `json:"httpClient"`
}

type rawHTTPClient struct {
	ConnectTimeout *json.Number `json:"connectTimeout"`
	ReadTimeout    *json.Number `json:"readTimeout"`
	MaxRetryCount  *json.Number `json:"maxRetryCount"`
}

// parseConfigBytes 解析并校验配置字节（§4.3 / §3.4）。
func parseConfigBytes(data []byte) (Config, error) {
	data = stripBOM(data)
	if len(bytes.TrimSpace(data)) == 0 {
		return Config{}, configErr("配置文件为空")
	}
	if err := detectDuplicateKeys(data); err != nil {
		return Config{}, err
	}

	var raw rawConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Config{}, configErr("配置文件 JSON 解析失败: %v", err)
	}
	// 拒绝根级以外更深嵌套（httpClient 外再嵌套对象）
	if dec.More() {
		return Config{}, configErr("配置文件 JSON 解析失败: 根对象后存在多余内容")
	}

	cfg := Config{
		AppKey:             strings.TrimSpace(raw.AppKey),
		Suite:              strings.TrimSpace(raw.Suite),
		MerchantPrivateKey: strings.TrimSpace(raw.MerchantPrivateKey),
		PlatformPublicKey:  strings.TrimSpace(raw.PlatformPublicKey),
		ServerRoot:         strings.TrimRight(strings.TrimSpace(raw.ServerRoot), "/"),
		BackupServerRoots:  append([]string(nil), raw.BackupServerRoots...),
		ExpiredSeconds:     defaultExpiredSeconds,
		HTTPClient: HTTPClientConfig{
			ConnectTimeout: defaultConnectTimeout,
			ReadTimeout:    defaultReadTimeout,
			MaxRetryCount:  defaultMaxRetryCount,
		},
	}

	if err := validateRequired(&cfg); err != nil {
		return Config{}, err
	}
	if err := parseExpiredSeconds(raw.ExpiredSeconds, &cfg); err != nil {
		return Config{}, err
	}
	if err := parseHTTPClient(raw.HTTPClient, &cfg); err != nil {
		return Config{}, err
	}
	if err := validateServerRoot(cfg.ServerRoot); err != nil {
		return Config{}, err
	}
	for i, root := range cfg.BackupServerRoots {
		normalized := strings.TrimRight(strings.TrimSpace(root), "/")
		cfg.BackupServerRoots[i] = normalized
		if err := validateBackupServerRoot(i+1, normalized); err != nil {
			return Config{}, err
		}
	}
	if _, ok := validSuites[cfg.Suite]; !ok {
		return Config{}, configErr("不支持的算法套件: %s", cfg.Suite)
	}
	return cfg, nil
}

func validateRequired(cfg *Config) error {
	if cfg.AppKey == "" {
		return configErr("配置文件缺少必填项: appKey")
	}
	if cfg.Suite == "" {
		return configErr("配置文件缺少必填项: suite")
	}
	if cfg.MerchantPrivateKey == "" {
		return configErr("配置文件缺少必填项: merchantPrivateKey")
	}
	if cfg.PlatformPublicKey == "" {
		return configErr("配置文件缺少必填项: platformPublicKey")
	}
	if cfg.ServerRoot == "" {
		return configErr("配置文件缺少必填项: serverRoot")
	}
	return nil
}

func parseExpiredSeconds(num *json.Number, cfg *Config) error {
	if num == nil {
		return nil
	}
	v, err := parsePositiveInt64("expiredSeconds", num)
	if err != nil {
		return err
	}
	cfg.ExpiredSeconds = v
	return nil
}

func parseHTTPClient(raw *rawHTTPClient, cfg *Config) error {
	if raw == nil {
		return nil
	}
	var err error
	if raw.ConnectTimeout != nil {
		if cfg.HTTPClient.ConnectTimeout, err = parsePositiveInt("connectTimeout", raw.ConnectTimeout); err != nil {
			return err
		}
	}
	if raw.ReadTimeout != nil {
		if cfg.HTTPClient.ReadTimeout, err = parsePositiveInt("readTimeout", raw.ReadTimeout); err != nil {
			return err
		}
	}
	if raw.MaxRetryCount != nil {
		if cfg.HTTPClient.MaxRetryCount, err = parseNonNegativeInt("maxRetryCount", raw.MaxRetryCount); err != nil {
			return err
		}
	}
	return nil
}

func parsePositiveInt(field string, num *json.Number) (int, error) {
	v, err := num.Int64()
	if err != nil {
		return 0, configErr("配置字段 %s 类型非法: %v", field, err)
	}
	if v <= 0 || v > math.MaxInt32 {
		return 0, configErr("配置字段 %s 类型非法: %v", field, v)
	}
	return int(v), nil
}

func parseNonNegativeInt(field string, num *json.Number) (int, error) {
	v, err := num.Int64()
	if err != nil {
		return 0, configErr("配置字段 %s 类型非法: %v", field, err)
	}
	if v < 0 || v > math.MaxInt32 {
		return 0, configErr("配置字段 %s 类型非法: %v", field, v)
	}
	return int(v), nil
}

func parsePositiveInt64(field string, num *json.Number) (int64, error) {
	v, err := num.Int64()
	if err != nil {
		return 0, configErr("配置字段 %s 类型非法: %v", field, err)
	}
	if v <= 0 {
		return 0, configErr("expiredSeconds 须为正整数")
	}
	return v, nil
}

func validateServerRoot(serverRoot string) error {
	return validateGatewayURL("serverRoot", serverRoot)
}

func validateBackupServerRoot(index int, serverRoot string) error {
	field := "backupServerRoots[" + itoa(index) + "]"
	return validateGatewayURL(field, serverRoot)
}

func validateGatewayURL(field, serverRoot string) error {
	if serverRoot == "" {
		return configErr("%s 不是合法 URL: 空值", field)
	}
	u, err := url.Parse(serverRoot)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return configErr("%s 不是合法 URL: %s", field, serverRoot)
	}
	if strings.ToLower(u.Scheme) != "https" {
		return configErr("%s 须为 HTTPS 绝对 URL: %s", field, serverRoot)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return configErr("%s 不得含 query 或 fragment: %s", field, serverRoot)
	}
	return nil
}

func stripBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}

// detectDuplicateKeys 使用 json.Decoder.Token() 预扫对象键（§4.4 K21）。
func detectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	type objFrame struct {
		keys      map[string]struct{}
		expectKey bool
	}
	type frame struct {
		obj   *objFrame
		array bool
	}
	var stack []frame

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return configErr("配置文件 JSON 解析失败: %v", err)
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, frame{obj: &objFrame{keys: make(map[string]struct{}), expectKey: true}})
			case '[':
				stack = append(stack, frame{array: true})
			case '}', ']':
				if len(stack) == 0 {
					return configErr("配置文件 JSON 解析失败: 意外符号 %q", v)
				}
				stack = stack[:len(stack)-1]
				markValueComplete(&stack)
			}
		case string:
			if len(stack) == 0 {
				continue
			}
			top := &stack[len(stack)-1]
			if top.array || top.obj == nil || !top.obj.expectKey {
				markValueComplete(&stack)
				continue
			}
			if _, dup := top.obj.keys[v]; dup {
				return configErr("配置字段 %s 重复: 对象键不得重复", v)
			}
			top.obj.keys[v] = struct{}{}
			top.obj.expectKey = false
		default:
			markValueComplete(&stack)
		}
	}
}

func markValueComplete(stack *[]frame) {
	for i := len(*stack) - 1; i >= 0; i-- {
		if (*stack)[i].array {
			continue
		}
		if (*stack)[i].obj != nil {
			(*stack)[i].obj.expectKey = true
		}
		return
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
