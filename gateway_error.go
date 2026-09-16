package wop

import "fmt"

// GatewayResponseError 表示网关 HTTP 非 2xx 响应（§7.5 K5）。
type GatewayResponseError struct {
	StatusCode int
	Body       []byte
}

func (e *GatewayResponseError) Error() string {
	return fmt.Sprintf("WOP 网关返回 HTTP %d（响应体 %d 字节）", e.StatusCode, len(e.Body))
}

func is2xx(status int) bool { return status >= 200 && status <= 299 }
