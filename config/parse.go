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
	// defaultConnectTimeout 缺省 TCP 连接超时（ms，§3.3）。
	defaultConnectTimeout = 10000
	// defaultReadTimeout 缺省读响应超时（ms）。
	defaultReadTimeout    = 30000
	// defaultMaxRetryCount 缺省跨域名重试上限。
	defaultMaxRetryCount  = 3
	// defaultExpiredSeconds 缺省出向签名窗口（秒）。
	defaultExpiredSeconds = int64(1800)
)

// validSuites 配置层套件白名单（§3.4，与核心 suiteRegistry 同源维护）。
var validSuites = map[string]struct{}{
	"WOP-RSA2048-SHA256": {},
	"WOP-RSA3072-SHA256": {},
	"WOP-RSA4096-SHA256": {},
	"WOP-SM2-SM3":        {},
}

// rawConfig 是 JSON 原始配置的中间绑定结构（camelCase 字段名）。
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

// rawHTTPClient 是 httpClient 对象的原始绑定（指针字段区分缺省与显式零值）。
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

// validateRequired 校验必填字段非空（§3.4，缺项即 configuration）。
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

// parseExpiredSeconds 解析 expiredSeconds（正整数，缺省 1800）。
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

// parseHTTPClient 解析 httpClient 对象（一层嵌套上限，缺省 10000/30000/3）。
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

// parsePositiveInt 解析正整数字段（类型不符/越界/非正数即 configuration）。
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

// parseNonNegativeInt 解析非负整数字段。
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

// parsePositiveInt64 解析正整数字段（long 域）。
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

// validateServerRoot 校验主网关地址（K20：HTTPS 绝对 URL，无 query/fragment）。
func validateServerRoot(serverRoot string) error {
	return validateGatewayURL("serverRoot", serverRoot)
}

// validateBackupServerRoot 校验备用网关地址（逐项，错误消息带索引）。
func validateBackupServerRoot(index int, serverRoot string) error {
	field := "backupServerRoots[" + itoa(index) + "]"
	return validateGatewayURL(field, serverRoot)
}

// validateGatewayURL 网关地址统一校验：URL 语法、HTTPS scheme、query/fragment 拒绝。
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

// stripBOM 剥离 UTF-8 BOM（§4.3 容忍并剥离）。
func stripBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}

// jsonFrame 是重复键预扫的解析栈帧：对象帧携带已见键集与期望位，数组帧仅占位。
type jsonFrame struct {
	obj   *jsonObjFrame
	array bool
}

// jsonObjFrame 对象帧：已见键集与期望键位。
type jsonObjFrame struct {
	keys      map[string]struct{}
	expectKey bool
}

// detectDuplicateKeys 使用 json.Decoder.Token() 预扫对象键（§4.4 K21）。
func detectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var stack []jsonFrame

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
				stack = append(stack, jsonFrame{obj: &jsonObjFrame{keys: make(map[string]struct{}), expectKey: true}})
			case '[':
				stack = append(stack, jsonFrame{array: true})
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

// markValueComplete 标记栈顶对象进入期望键状态（数组帧跳过）。
func markValueComplete(stack *[]jsonFrame) {
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

// itoa 极简整数转十进制串（错误消息索引用）。
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
