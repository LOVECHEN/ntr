package quic

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
)

// TestQUICSelfLoop:NTR quic DialBase ↔ ListenBase 经真 UDP+QUIC 往返一条流,验 UDP-base QUIC 传输
// (自签证书 + 内建 TLS + OpenStream/AcceptStream)可靠双向。
func TestQUICSelfLoop(t *testing.T) {
	built, err := Build(context.Background(), Config{Insecure: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := built.(*Transport)

	ln, err := tr.ListenBase(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		buf := make([]byte, 256)
		n, _ := s.Read(buf)
		_, _ = s.Write(buf[:n])
		time.Sleep(300 * time.Millisecond)
	}()

	// 客户端 SNI 取监听地址 IP(自签证书 insecure=true 跳过校验)。
	c, err := tr.DialBase(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("DialBase: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	msg := []byte("quic-selfloop-hello-42")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo 不符:got %q want %q", got, msg)
	}
}

var _ = link.Stream(nil)
