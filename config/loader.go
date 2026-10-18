package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// EnvConfigFile 显式配置路径覆盖（§4.2 优先级 1）。
	EnvConfigFile = "WOP_SDK_CONFIG_FILE"
	// EnvConfig 环境变量配置路径（§4.2 优先级 2）。
	EnvConfig = "WOP_SDK_CONFIG"
)

var (
	// cacheMu 保护加载缓存（K13：无自动失效，仅 clearCache 显式清除）。
	cacheMu sync.Mutex
	// cache 以规范化资源位置为 key 的配置缓存（同一位置返回同一快照）。
	cache = make(map[string]Config)
)

// LoadDefault 按 §4.2 自动发现并加载配置；同一位置缓存解析结果。
func LoadDefault() (Config, error) {
	candidates := defaultDiscoveryCandidates()
	for _, c := range candidates {
		if c.explicit && !c.readable {
			return Config{}, configErr("配置文件不可读: %s", c.display)
		}
		if !c.readable {
			continue
		}
		return Load(c.path)
	}
	var b strings.Builder
	b.WriteString("未找到可读的配置文件，已尝试：")
	for i, c := range candidates {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.display)
	}
	return Config{}, configErr("%s", b.String())
}

// discoveryCandidate 是单个发现来源：路径、展示名、可读性与是否显式指定。
type discoveryCandidate struct {
	path     string
	display  string
	readable bool
	explicit bool
}

// defaultDiscoveryCandidates 按 §4.2 优先级枚举发现来源（显式 env 优先）。
func defaultDiscoveryCandidates() []discoveryCandidate {
	var out []discoveryCandidate

	if p := strings.TrimSpace(os.Getenv(EnvConfigFile)); p != "" {
		out = append(out, makeCandidate(p, p, true))
		return out
	}
	if p := strings.TrimSpace(os.Getenv(EnvConfig)); p != "" {
		out = append(out, makeCandidate(p, p, true))
		return out
	}

	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()

	paths := []struct {
		path    string
		display string
	}{
		{filepath.Join(cwd, "config", "wopSdkConfig.json"), "{cwd}/config/wopSdkConfig.json"},
		{filepath.Join(cwd, "wopSdkConfig.json"), "{cwd}/wopSdkConfig.json"},
		{filepath.Join(home, ".wop", "wopSdkConfig.json"), "{userHome}/.wop/wopSdkConfig.json"},
		{embeddedConfigPath, "embedded:config/wopSdkConfig.json"},
	}
	for _, item := range paths {
		out = append(out, makeCandidate(item.path, expandDisplay(item.display, cwd, home), false))
	}
	return out
}

// expandDisplay 返回候选路径的展开展示形式（错误消息用）。
func expandDisplay(template, cwd, home string) string {
	s := strings.ReplaceAll(template, "{cwd}", cwd)
	return strings.ReplaceAll(s, "{userHome}", home)
}

// makeCandidate 组装候选并测定可读性。
func makeCandidate(path, display string, explicit bool) discoveryCandidate {
	readable := false
	if path == embeddedConfigPath {
		readable = len(embeddedDefaultConfig) > 0
	} else {
		info, err := os.Stat(path)
		readable = err == nil && !info.IsDir()
	}
	return discoveryCandidate{path: path, display: display, readable: readable, explicit: explicit}
}

// Load 从显式文件系统路径加载配置；同一规范化路径缓存复用。
func Load(path string) (Config, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return Config{}, configErr("配置路径为空")
	}

	cacheMu.Lock()
	if cfg, ok := cache[path]; ok {
		cacheMu.Unlock()
		return cfg, nil
	}
	cacheMu.Unlock()

	data, err := readConfigFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg, err := parseConfigBytes(data)
	if err != nil {
		return Config{}, err
	}

	cacheMu.Lock()
	cache[path] = cfg
	cacheMu.Unlock()
	return cfg, nil
}

// readConfigFile 读取配置文件（§4.3：UTF-8 剥 BOM，空文件报错）。
func readConfigFile(path string) ([]byte, error) {
	if path == embeddedConfigPath {
		if len(embeddedDefaultConfig) == 0 {
			return nil, configErr("打包资源配置缺失: config/wopSdkConfig.json")
		}
		return embeddedDefaultConfig, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, configErr("读取配置文件失败: %s: %v", path, err)
	}
	return data, nil
}

// ClearCache 清除加载缓存（测试 / 配置轮换编排，§5 K26）。
func ClearCache() {
	cacheMu.Lock()
	cache = make(map[string]Config)
	cacheMu.Unlock()
}

// NormalizeCacheKey 供测试断言缓存键。
func NormalizeCacheKey(path string) string {
	return filepath.Clean(strings.TrimSpace(path))
}

// FormatDiscoveryList 供测试列出发现候选。
func FormatDiscoveryList() string {
	var parts []string
	for _, c := range defaultDiscoveryCandidates() {
		parts = append(parts, fmt.Sprintf("%s=%v", c.display, c.readable))
	}
	return strings.Join(parts, "; ")
}
