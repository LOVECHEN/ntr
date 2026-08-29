package h2

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
)

// TestH2SelfLoop:NTR h2 客户端(h2c)↔ 服务端(双模,此处走 h2c)经真 TCP 单请求全双工往返。
func TestH2SelfLoop(t *testing.T) {
	built, err := Build(context.Background(), Config{Path: "/p", Method: "PUT"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := built.(*Transport)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s, err := tr.ServerWrap(context.Background(), connStream{c})
		if err != nil {
			return
		}
		buf := make([]byte, 256)
		n, _ := s.Read(buf)
		_, _ = s.Write(buf[:n])
		time.Sleep(200 * time.Millisecond)
		_ = s.Close()
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cs, err := tr.ClientWrap(context.Background(), connStream{c})
	if err != nil {
		t.Fatalf("ClientWrap: %v", err)
	}
	defer cs.Close()
	_ = cs.SetDeadline(time.Now().Add(5 * time.Second))

	msg := []byte("h2-selfloop-hello-42")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(cs, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo 不符:got %q want %q", got, msg)
	}
}

type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

var _ link.Stream = connStream{}
