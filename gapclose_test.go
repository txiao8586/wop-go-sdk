package wop

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkconfig "github.com/wop-platform/wop-go-sdk/config"
)

// 本文件闭合覆盖率门禁下的既有错误分支缺口（与附录 I 无关的工厂门红线 ≥98%）。

func TestGatewayErrorMessageFormat(t *testing.T) { // spec:§7.5 K5 消息格式（不内嵌 body 全文）
	e := &GatewayResponseError{StatusCode: 502, Body: []byte("ab")}
	if got := e.Error(); got != "WOP 网关返回 HTTP 502（响应体 2 字节）" {
		t.Errorf("Error() = %q", got)
	}
}

func TestValidateAPIPathAllBranches(t *testing.T) { // spec:§7.7 path 语法全分支
	for _, tc := range []struct {
		path string
		want string
	}{
		{"", "请求 path 为空"},
		{"no-slash", "path 须以 / 开头"},
		{"//attacker.example/p", "path 不得以 // 开头"},
		{"/p?key=1", "path 不得含 query 或 fragment"},
		{"/p#frag", "path 不得含 query 或 fragment"},
		{"/http://evil/p", "path 不得为绝对 URL"},
	} {
		err := validateAPIPath(tc.path)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("validateAPIPath(%q) = %v, want 含 %q", tc.path, err, tc.want)
		}
	}
	if err := validateAPIPath("/ok/path"); err != nil {
		t.Errorf("合法 path 不应拒绝: %v", err)
	}
}

func TestWrapConfigErrorBothBranches(t *testing.T) {
	ce := wrapConfigError(&sdkconfig.Error{Message: "suite 非法"})
	if !strings.Contains(ce.Error(), "suite 非法") {
		t.Errorf("配置类错误透传消息, got %q", ce.Error())
	}
	ge := wrapConfigError(errors.New("io 冒烟"))
	if !strings.Contains(ge.Error(), "配置加载失败") || !strings.Contains(ge.Error(), "io 冒烟") {
		t.Errorf("未知错误须包裹, got %q", ge.Error())
	}
}

func TestRoundTripperTransportBridgesAndBlocksRedirect(t *testing.T) { // spec:§7.4.1 重定向关闭
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("final-ok"))
	}))
	defer srv.Close()

	tr := RoundTripperTransport(http.DefaultTransport, srv.URL)
	resp, err := tr.Send(RequestDraft{Method: "GET", Path: "/redirect", Headers: map[string]string{}})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("3xx 须原样返回（不跟随重定向）, got %d", resp.StatusCode)
	}
}

func TestNewDefaultHTTPClientTimeoutDefaults(t *testing.T) { // spec:§3.3 httpClient 缺省值
	c := newDefaultHTTPClient(HTTPClientSettings{}) // 全零 → 缺省 10000/30000
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.ResponseHeaderTimeout.Milliseconds() != 30000 {
		t.Errorf("缺省 readTimeout 应为 30000ms, got %v", tr.ResponseHeaderTimeout)
	}
	c2 := newDefaultHTTPClient(HTTPClientSettings{ConnectTimeout: 5, ReadTimeout: 7})
	tr2 := c2.Transport.(*http.Transport)
	if tr2.ResponseHeaderTimeout.Milliseconds() != 7 {
		t.Errorf("显式 readTimeout 应生效, got %v", tr2.ResponseHeaderTimeout)
	}
}

func TestNewMessageGCMKeyLengthGuard(t *testing.T) {
	suite, err := ParseSuite("WOP-RSA3072-SHA256")
	if err != nil {
		t.Fatalf("ParseSuite: %v", err)
	}
	if _, err := newMessageGCM(suite, make([]byte, 15)); err == nil {
		t.Errorf("密钥长度不符应拒绝")
	}
}

func TestSealEnvelopeRandomFailureBranches(t *testing.T) {
	c, err := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// CEK 段读失败
	if _, _, err := c.sealEnvelope([]byte("x"), bytes.NewReader(nil)); err == nil {
		t.Errorf("CEK 生成失败应报错")
	}
	// CEK 成功、IV 段读失败
	if _, _, err := c.sealEnvelope([]byte("x"), io.LimitReader(bytes.NewReader(bytes.Repeat([]byte{0x5A}, 32)), 32)); err == nil {
		t.Errorf("IV 生成失败应报错")
	}
}
