package mkcp

import (
	"context"
	"io"
	"testing"
	"time"
)

// TestMkcpSelfLoop:NTR mkcp DialBase ↔ ListenBase 经真 UDP 往返一条 KCP 会话,验 UDP-base 传输
// (自拨 UDP+KCP 客户端 ↔ UDP 监听+KCP accept 服务端)可靠有序、双向不阻塞。
func TestMkcpSelfLoop(t *testing.T) {
	built, err := Build(context.Background(), Config{Header: "none"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := built.(*Transport)

	ln, err := tr.ListenBase(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// 服务端:accept 一条 KCP 流,echo。
	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		buf := make([]byte, 256)
		n, _ := s.Read(buf)
		_, _ = s.Write(buf[:n])
		time.Sleep(300 * time.Millisecond) // 让客户端读到回写
	}()

	c, err := tr.DialBase(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("DialBase: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	msg := []byte("mkcp-selfloop-hello-42")
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
