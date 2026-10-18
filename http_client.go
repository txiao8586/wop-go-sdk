package wop

import (
	"context"
	"net"
	"net/http"
	"time"
)

// HTTPClientSettings 全局 HTTP 客户端参数（与 JSON httpClient 对象对应）。
type HTTPClientSettings struct {
	ConnectTimeout int
	ReadTimeout    int
	MaxRetryCount  int
}

// newDefaultHTTPClient 按全局参数构造默认 HTTP 客户端（缺省 10000/30000，重定向关闭 §7.4.1）。
func newDefaultHTTPClient(settings HTTPClientSettings) *http.Client {
	connect := settings.ConnectTimeout
	if connect <= 0 {
		connect = 10000
	}
	read := settings.ReadTimeout
	if read <= 0 {
		read = 30000
	}
	dialer := &net.Dialer{Timeout: time.Duration(connect) * time.Millisecond}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		ResponseHeaderTimeout: time.Duration(read) * time.Millisecond,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
