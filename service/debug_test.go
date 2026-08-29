package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
)

// TestDebugLogging:debug 关时静默、开时带 ntr-debug 前缀打印 —— 保证默认不刷屏、开后可查错。
func TestDebugLogging(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	defer SetDebug(false)

	SetDebug(false)
	debugf("不该出现 %d", 1)
	if buf.Len() != 0 {
		t.Fatalf("debug 关时不应打印,却有:%q", buf.String())
	}

	SetDebug(true)
	debugf("入站失败 %d", 42)
	got := buf.String()
	if !strings.Contains(got, "ntr-debug") || !strings.Contains(got, "入站失败 42") {
		t.Fatalf("debug 开时应打印带前缀的错误,得:%q", got)
	}
}

// TestIsNormalClose:EOF / 连接已关(含包装)算正常终止;真错误不算。
func TestIsNormalClose(t *testing.T) {
	if !isNormalClose(io.EOF) {
		t.Fatal("io.EOF 应算正常")
	}
	if !isNormalClose(net.ErrClosed) {
		t.Fatal("net.ErrClosed 应算正常")
	}
	if !isNormalClose(fmt.Errorf("read udp: %w", net.ErrClosed)) {
		t.Fatal("包装的 net.ErrClosed 应算正常")
	}
	if isNormalClose(errors.New("reality: 客户端缺 server-name")) {
		t.Fatal("真配置错误不应算正常终止(否则会被 debug 吞掉)")
	}
}
