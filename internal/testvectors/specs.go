// Package testvectors 黄金向量钉版拉取（对齐 java-sdk 构建期模式）：
// 真源 wop-platform/wop-specs，副本不落库，首次取用即按 ref+sha256 拉取校验，
// mismatch 即 panic（fail-closed）。升级流程见 CONTRIBUTING：先合 wop-specs PR，
// 再同步 specsRef 与 sha256s 钉版三件套。
package testvectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

const (
	specsRef = "a1f7feb5b4af5c9052149e2adfd2063caa102677"
	specsURL = "https://raw.githubusercontent.com/wop-platform/wop-specs/" + specsRef + "/"
)

var sha256s = map[string]string{
	"crypto/crypto-vectors.json":    "c7dd65740a1da9a5cfb804bca0c8b1bd7d4ab967adeb075297677a4bef148736",
	"interop/v1/interop-cases.json": "c920ca1a93ccb3899a659f59fed6ec4652cf9e1b3b58bbdac23c45ac3ed2353e",
}

var fetchOnce sync.Once

// Path 返回向量文件路径（crypto-vectors.json / interop-cases.json），首次调用拉取并校验。
func Path(name string) string {
	fetchOnce.Do(fetch)
	return filepath.Join(testdataDir(), name)
}

func testdataDir() string {
	// internal/testvectors → internal/testdata
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "testdata")
}

func fetch() {
	dir := testdataDir()
	for src, expected := range sha256s {
		resp, err := http.Get(specsURL + src)
		if err != nil {
			panic(fmt.Sprintf("wop-specs %s 拉取失败：%v", src, err))
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			panic(fmt.Sprintf("wop-specs %s 拉取失败：HTTP %d %v", src, resp.StatusCode, readErr))
		}
		sum := sha256.Sum256(data)
		if digest := hex.EncodeToString(sum[:]); digest != expected {
			panic(fmt.Sprintf("wop-specs %s sha256 mismatch：期望 %s 实得 %s；向量升级须先合 wop-specs PR 再同步钉版", src, expected, digest))
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(src)), data, 0o644); err != nil {
			panic(err)
		}
	}
}
