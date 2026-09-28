package wop

import "fmt"

// GatewayResponseError 表示网关 HTTP 非 2xx 响应（§7.5 K5）。
type GatewayResponseError struct {
	StatusCode int
	Body       []byte
}

// Error 实现 error 接口：含状态码与响应体字节数，不内嵌 body 全文（防日志膨胀，K5）。
func (e *GatewayResponseError) Error() string {
	return fmt.Sprintf("WOP 网关返回 HTTP %d（响应体 %d 字节）", e.StatusCode, len(e.Body))
}

// is2xx 判定 HTTP 状态码是否为 2xx（K5：仅 2xx 进入验签）。
func is2xx(status int) bool { return status >= 200 && status <= 299 }
