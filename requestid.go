package wop

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"os"
	"strings"
)

// outboundLog 出向日志（wop-specs 附录 I/I3 日志义务）：出向请求构造点打印最终
// x-wop-request-id 值。该值为非敏感标识，豁免凭证脱敏纪律——禁止打码、禁止吞并；
// 商户可经 SetOutboundLogOutput 重定向（如 io.Discard 静默），缺省写 stderr。
var outboundLog = log.New(os.Stderr, "", log.LstdFlags)

// SetOutboundLogOutput 重定向出向日志输出（缺省 stderr；传 io.Discard 可静默）。
func SetOutboundLogOutput(w io.Writer) {
	outboundLog.SetOutput(w)
}

// requestIDTrimChars 附录 I/I2 trim 集 = G2 TrimAll 空白类（空格、\t、\n、\x0B、\f、\r）。
// 不用 strings.TrimSpace（Unicode 空白超集，跨仓口径不一致）。
const requestIDTrimChars = " \t\n\x0B\f\r"

// requestIDGen 缺省 requestId 生成器（附录 I/I3：可注入替换——测试确定性锚，
// 与 clock/nonce 注入同级）。包内变量，测试可整体替换。
var requestIDGen = defaultRequestID

// defaultRequestID 缺省生成：UUID 去连字符（小写 32 位 hex，v4 语义）。
// crypto/rand.Read 在受支持平台恒成功填满（Go 文档保证，不返回错误）。
func defaultRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return hex.EncodeToString(b[:])
}

// resolveRequestID 校验并归一化商户 requestId（附录 I/I2，构造即拒，configuration 类）：
//  1. trim 前按**原值**逐字符扫描控制字符（< 0x20 或 == 0x7F，含 CR/LF/NUL/DEL）——防头注入；
//  2. trim（G2 TrimAll 同集）后为空 → 视为未设置（ok=false，调用方走缺省生成）；
//  3. trim 后 UTF-8 编码字节 > 128 → 拒（len(string) 即 UTF-8 字节数，网关 header 缓冲按字节计）。
//
// 返回 trim 后上行值；ok=false 表示未设置。
func resolveRequestID(raw string) (resolved string, ok bool, err error) {
	if raw == "" {
		return "", false, nil
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "", false, newError(CodeConfiguration, "requestId 含控制字符（防头注入）: %d", r)
		}
	}
	trimmed := strings.Trim(raw, requestIDTrimChars)
	if trimmed == "" {
		return "", false, nil
	}
	if len(trimmed) > 128 {
		return "", false, newError(CodeConfiguration, "requestId UTF-8 字节长度不能超过 128（实际 %d）", len(trimmed))
	}
	return trimmed, true, nil
}
