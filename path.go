package wop

import (
	"strings"
)

// validateAPIPath 校验 execute/buildRequest 的纯 API 路径（§7.7）。
func validateAPIPath(path string) error {
	if path == "" {
		return newError(CodeConfiguration, "请求 path 为空")
	}
	if !strings.HasPrefix(path, "/") {
		return newError(CodeConfiguration, "path 须以 / 开头")
	}
	if strings.HasPrefix(path, "//") {
		return newError(CodeConfiguration, "path 不得以 // 开头")
	}
	if strings.Contains(path, "?") || strings.Contains(path, "#") {
		return newError(CodeConfiguration, "path 不得含 query 或 fragment")
	}
	if strings.Contains(path, "://") {
		return newError(CodeConfiguration, "path 不得为绝对 URL")
	}
	return nil
}

// joinServerRootAndPath 按 K23 字符串拼接 serverRoot 与 path。
func joinServerRootAndPath(serverRoot, path string) string {
	return strings.TrimRight(serverRoot, "/") + "/" + strings.TrimLeft(path, "/")
}
