package wop

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// genRSA2048KeyMaterial 测试现场生成 RSA-2048 密钥对（PKCS#8 私钥 / SPKI 公钥，标准 Base64）。
func genRSA2048KeyMaterial(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA-2048 密钥失败: %v", err)
	}
	privDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("序列化私钥失败: %v", err)
	}
	pubDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("序列化公钥失败: %v", err)
	}
	return base64.StdEncoding.EncodeToString(privDer), base64.StdEncoding.EncodeToString(pubDer)
}

func newRSA2048Client(t *testing.T) *Client {
	t.Helper()
	priv, pub := genRSA2048KeyMaterial(t)
	c, err := NewClient(Config{
		AppKey:             "app_test_001",
		SecurityReq:        "WOP-RSA2048-SHA256",
		MerchantPrivateKey: priv,
		PlatformPublicKey:  pub,
	})
	if err != nil {
		t.Fatalf("NewClient(RSA2048): %v", err)
	}
	return c
}

// TestRsa2048Suite_DefaultSupported spec:crypto-strategy-spec E1 扩展位（RSA2048 默认支持）。
func TestRsa2048Suite_DefaultSupported(t *testing.T) {
	s, err := ParseSuite("WOP-RSA2048-SHA256")
	if err != nil {
		t.Fatalf("RSA2048 套件应默认支持: %v", err)
	}
	if s.Family() != FamilyRSA || s.KeyBits() != 2048 {
		t.Errorf("family/bits = %s/%d, want RSA/2048", s.Family(), s.KeyBits())
	}
	if s.DigestTag() != "sha-256" || s.MessageAlgorithm() != "AES-256-GCM" {
		t.Errorf("digestTag/message = %s/%s, want sha-256/AES-256-GCM", s.DigestTag(), s.MessageAlgorithm())
	}
	if got := s.signatureLen(); got != 256 {
		t.Errorf("signatureLen = %d, want 256（2048 位）", got)
	}
	// 跨族仍拒绝
	if _, err := ParseSuite("WOP-RSA2048-SM3"); err == nil {
		t.Errorf("WOP-RSA2048-SM3 跨族应拒绝")
	}
	// 端到端：2048 位密钥装配 + L2 信封 + buildRequest
	c := newRSA2048Client(t)
	if _, err := c.BuildRequest("POST", "/p", []byte(`{"k":1}`), Level2,
		WithTimestamp(1), WithNonce("n")); err != nil {
		t.Fatalf("RSA2048 L2 构建失败: %v", err)
	}
}

// TestRequestIdPassthrough spec:wop-sdk-spec 附录 I（x-wop-request-id）。
func TestRequestIdPassthrough(t *testing.T) {
	c, err := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	t.Run("显式传值 trim 后原值上行", func(t *testing.T) {
		d, err := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"), WithRequestID("  req-001  "))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if got := d.Headers[HeaderRequestId]; got != "req-001" {
			t.Errorf("requestId = %q, want %q（trim 后原值，禁止改写）", got, "req-001")
		}
	})

	t.Run("恒不入签且带不带透传头签名同值", func(t *testing.T) { // spec:附录 I/I1
		withID, _ := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"), WithRequestID("req-001"))
		without, _ := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"))
		for _, d := range []RequestDraft{withID, without} {
			names := strings.Split(strings.Split(d.Headers[HeaderSign], "/")[2], ";")
			for _, n := range names {
				if n == HeaderRequestId {
					t.Fatalf("x-wop-request-id 不得进入 signedHeaders")
				}
			}
		}
		if withID.Headers[HeaderSign] != without.Headers[HeaderSign] {
			t.Errorf("带/不带透传头 x-wop-sign 字节不同值（附录 I/I1 验收锚）")
		}
	})

	t.Run("未传或空白缺省生成UUID32且每次新鲜", func(t *testing.T) { // spec:附录 I/I3
		uuidRe := regexp.MustCompile(`^[0-9a-f]{32}$`)
		a, _ := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"))
		if !uuidRe.MatchString(a.Headers[HeaderRequestId]) {
			t.Errorf("缺省 requestId = %q, want 小写 32 位 hex（UUID 去连字符）", a.Headers[HeaderRequestId])
		}
		b, _ := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"))
		if a.Headers[HeaderRequestId] == b.Headers[HeaderRequestId] {
			t.Errorf("缺省 requestId 每次构建须新鲜")
		}
		// 空格 trim 后为空 → 视为未设置，走缺省生成（\t/\n 属控制字符，trim 前扫描即拒）
		blank, err := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"), WithRequestID("   "))
		if err != nil {
			t.Fatalf("空白 requestId 应走缺省生成: %v", err)
		}
		if !uuidRe.MatchString(blank.Headers[HeaderRequestId]) {
			t.Errorf("空白 requestId 缺省生成 = %q", blank.Headers[HeaderRequestId])
		}
	})

	t.Run("控制字符trim前扫描即拒", func(t *testing.T) { // spec:附录 I/I2
		for _, bad := range []string{"a\nb", "a\rb", "a\x00b", "a\x7fb", "a\tb", "\nlead", "trail\r", " \t ", "\x00", "\x7f"} {
			_, err := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"), WithRequestID(bad))
			if err == nil {
				t.Fatalf("requestId %q 含控制字符应拒绝", bad)
			}
			we, ok := err.(*Error)
			if !ok || we.Code != CodeConfiguration {
				t.Errorf("requestId %q: err = %v, want configuration", bad, err)
			}
			if !strings.Contains(err.Error(), "控制字符") {
				t.Errorf("requestId %q: 消息须含「控制字符」，got %q", bad, err.Error())
			}
		}
	})

	t.Run("长度按trim后UTF8字节计", func(t *testing.T) { // spec:附录 I/I2
		if _, err := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"), WithRequestID(strings.Repeat("x", 128))); err != nil {
			t.Errorf("128 ASCII 字节应通过: %v", err)
		}
		_, err129 := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"), WithRequestID(strings.Repeat("x", 129)))
		if err129 == nil || !strings.Contains(err129.Error(), "实际 129") {
			t.Errorf("129 字节应拒绝且消息含实际值, got %v", err129)
		}
		if _, err := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"), WithRequestID(strings.Repeat("标", 42))); err != nil {
			t.Errorf("42 中文字符（126 字节）应通过: %v", err)
		}
		if _, err := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"), WithRequestID(strings.Repeat("标", 43))); err == nil {
			t.Errorf("43 中文字符（129 字节）应拒绝")
		}
	})

	t.Run("日志义务打印最终头值", func(t *testing.T) { // spec:附录 I/I3
		var buf bytes.Buffer
		prev := outboundLog.Writer()
		SetOutboundLogOutput(&buf)
		defer SetOutboundLogOutput(prev)
		if _, err := c.BuildRequest("GET", "/p", nil, Level0, WithTimestamp(1), WithNonce("n"), WithRequestID("logreq001")); err != nil {
			t.Fatalf("build: %v", err)
		}
		if !strings.Contains(buf.String(), fmt.Sprintf("%s=logreq001 GET /p", HeaderRequestId)) {
			t.Errorf("出向日志须含最终头值, got %q", buf.String())
		}
	})

	t.Run("注入生成器后Execute路径透传", func(t *testing.T) { // spec:附录 I/I3 注入锚
		prev := requestIDGen
		requestIDGen = func() string { return "gen-anchor-001" }
		defer func() { requestIDGen = prev }()
		d, err := c.BuildRequest("POST", "/p", []byte(`{}`), Level0, WithTimestamp(1), WithNonce("n"))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if d.Headers[HeaderRequestId] != "gen-anchor-001" {
			t.Errorf("注入生成器未生效: %q", d.Headers[HeaderRequestId])
		}
	})
}

// TestRequestIDHeaderAlwaysPresentAndNeverSigned L0/L2 双级别不变式：头恒存在、恒不在签名集合。
func TestRequestIDHeaderAlwaysPresentAndNeverSigned(t *testing.T) {
	c := newRSA2048Client(t)
	for _, tc := range []struct {
		level Level
		body  []byte
	}{{Level0, []byte(`{}`)}, {Level2, []byte(`{"secret":true}`)}} {
		d, err := c.BuildRequest("POST", "/p", tc.body, tc.level, WithTimestamp(1), WithNonce("n"))
		if err != nil {
			t.Fatalf("%s: build: %v", tc.level, err)
		}
		if d.Headers[HeaderRequestId] == "" {
			t.Errorf("%s: x-wop-request-id 头恒存在（附录 I/I3）", tc.level)
		}
		names := strings.Split(strings.Split(d.Headers[HeaderSign], "/")[2], ";")
		for _, n := range names {
			if n == HeaderRequestId {
				t.Errorf("%s: 透传头混入 signedHeaders", tc.level)
			}
		}
	}
}
