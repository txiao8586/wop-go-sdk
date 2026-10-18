package wop

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
)

// RSA2048 套件冻结向量（fixture 为真源字节副本，禁手改）：
// docs/reviews/2026-10-18-sdk-pr-review/rsa2048-vectors.json。
// 701185f 引入 WOP-RSA2048-SHA256 但向量后补，本文件负责字节级钉死。
const rsa2048VectorsPath = "internal/testdata/rsa2048-vectors.json"

type rsa2048Vectors struct {
	Inputs struct {
		Message string `json:"message"`
	} `json:"inputs"`
	Keys struct {
		RSA2048 struct {
			PublicSpkiB64   string `json:"publicSpkiB64"`
			PrivatePkcs8B64 string `json:"privatePkcs8B64"`
		} `json:"rsa2048"`
	} `json:"keys"`
	Signature []struct {
		ID              string `json:"id"`
		Key             string `json:"key"`
		Message         string `json:"message"`
		ExpectedSigB64u string `json:"expectedSigB64u"`
		SigLenBytes     int    `json:"sigLenBytes"`
		B64uLen         int    `json:"b64uLen"`
	} `json:"signature"`
	KeyEncrypt []struct {
		ID                string `json:"id"`
		Key               string `json:"key"`
		CipherB64u        string `json:"cipherB64u"`
		ExpectedPlaintext string `json:"expectedPlaintext"`
		Params            string `json:"params"`
		Expect            string `json:"expect"`
	} `json:"keyEncrypt"`
}

func loadRSA2048Vectors(t *testing.T) *rsa2048Vectors {
	t.Helper()
	raw, err := os.ReadFile(rsa2048VectorsPath)
	if err != nil {
		t.Fatalf("读取 RSA2048 向量 fixture 失败：%v", err)
	}
	var v rsa2048Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("解析 RSA2048 向量 fixture 失败：%v", err)
	}
	return &v
}

// rsa2048Fixture 装配套件与密钥对（套件 ID 固定 WOP-RSA2048-SHA256）。
func rsa2048Fixture(t *testing.T) (Suite, *pubKey, *privKey) {
	t.Helper()
	v := loadRSA2048Vectors(t)
	suite := mustSuite(t, "WOP-RSA2048-SHA256")
	pub := &pubKey{}
	var err error
	if pub.rsa, err = parseRSAPublicKey(v.Keys.RSA2048.PublicSpkiB64); err != nil {
		t.Fatalf("RSA2048 公钥: %v", err)
	}
	priv := &privKey{}
	if priv.rsa, err = parseRSAPrivateKey(v.Keys.RSA2048.PrivatePkcs8B64); err != nil {
		t.Fatalf("RSA2048 私钥: %v", err)
	}
	return suite, pub, priv
}

// a) PKCS#1 v1.5 + SHA-256 确定性 → 签名字节级一致（含 256B/342 字符定长与自验签）。
func TestRSA2048Vectors_SignByteLevel(t *testing.T) {
	v := loadRSA2048Vectors(t)
	suite, pub, priv := rsa2048Fixture(t)

	found := false
	for _, sv := range v.Signature {
		if sv.ID != "rsa2048-sign" {
			continue
		}
		found = true
		got, err := signMessage(suite, priv, nil, []byte(sv.Message), nil)
		if err != nil {
			t.Fatalf("%s 签名: %v", sv.ID, err)
		}
		if got != sv.ExpectedSigB64u {
			t.Errorf("%s 签名字节不一致:\n got %s\nwant %s", sv.ID, got, sv.ExpectedSigB64u)
		}
		if raw := mustDecodeB64u(t, got); len(raw) != sv.SigLenBytes {
			t.Errorf("%s 签名长度 = %d 字节, want %d", sv.ID, len(raw), sv.SigLenBytes)
		}
		if len(got) != sv.B64uLen {
			t.Errorf("%s b64u 长度 = %d, want %d", sv.ID, len(got), sv.B64uLen)
		}
		if err := verifyMessage(suite, pub, []byte(sv.Message), got); err != nil {
			t.Errorf("%s 自验签失败: %v", sv.ID, err)
		}
	}
	if !found {
		t.Fatal("fixture 缺 rsa2048-sign 向量（完整性哨兵）")
	}
}

// b) OAEP unwrap：冻结密文解包 == 冻结明文（F2：OAEP 双 SHA-256 + 空 label）。
func TestRSA2048Vectors_OAEPUnwrap(t *testing.T) {
	v := loadRSA2048Vectors(t)
	suite, _, priv := rsa2048Fixture(t)

	found := false
	for _, ke := range v.KeyEncrypt {
		if ke.ID != "oaep2048-unwrap" {
			continue
		}
		found = true
		plain, err := unwrapDEKPayload(suite, priv, ke.CipherB64u)
		if err != nil {
			t.Fatalf("%s unwrap: %v", ke.ID, err)
		}
		if string(plain) != ke.ExpectedPlaintext {
			t.Errorf("%s 解包明文 = %q, want %q", ke.ID, plain, ke.ExpectedPlaintext)
		}
	}
	if !found {
		t.Fatal("fixture 缺 oaep2048-unwrap 向量（完整性哨兵）")
	}
}

// c) 套件签名定长前置校验（与 3072 系 383B 拒收同构）：2048 位恒 256B/342 字符。
func TestRSA2048Suite_SignatureFixedLength(t *testing.T) {
	suite, pub, _ := rsa2048Fixture(t)
	if got := suite.signatureLen(); got != 256 {
		t.Errorf("WOP-RSA2048-SHA256 signatureLen = %d, want 256", got)
	}
	msg := []byte("POST\n/api/x")
	if err := verifyMessage(suite, pub, msg, EncodeB64URL(make([]byte, 255))); err == nil {
		t.Error("255B RSA2048 签名应拒绝（2048 位恒 256B/342 字符）")
	} else if err.(*Error).Code != CodeParse {
		t.Errorf("RSA2048 错长: 错误类 = %s, want CodeParse", err.(*Error).Code)
	}
	if got := len(EncodeB64URL(make([]byte, 256))); got != 342 {
		t.Errorf("256B 签名 b64u 长度 = %d, want 342", got)
	}
}

// d) L2 封装往返：2048 密钥 DEK 包装 + AES-256-GCM 报文封解，一例走通全链。
func TestRSA2048Vectors_L2EnvelopeRoundtrip(t *testing.T) {
	suite, pub, priv := rsa2048Fixture(t)

	plaintext := []byte("RSA2048 L2 envelope roundtrip 明文")
	cek := make([]byte, 32) // AES-256-GCM key
	iv := make([]byte, 12)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	wrapped, err := wrapDEKPayload(suite, pub,
		[]byte(buildDekPayload(suite.MessageAlgorithm(), cek, iv)), nil)
	if err != nil {
		t.Fatalf("2048 OAEP 包装 DEK: %v", err)
	}
	dekRaw, err := unwrapDEKPayload(suite, priv, wrapped)
	if err != nil {
		t.Fatalf("2048 OAEP 解包 DEK: %v", err)
	}
	dek, err := parseDekPayload(string(dekRaw))
	if err != nil {
		t.Fatalf("DEK 载荷解析: %v", err)
	}
	if !dek.matchesSuite(suite) {
		t.Fatalf("DEK alg %s 与套件 %s 不匹配", dek.alg, suite.SecurityReq())
	}

	ct, err := sealMessage(suite, plaintext, cek, iv)
	if err != nil {
		t.Fatalf("AES-256-GCM 封装: %v", err)
	}
	got, err := openMessage(suite, ct, dek.key, dek.iv)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("L2 往返: plain=%q err=%v", got, err)
	}
}
