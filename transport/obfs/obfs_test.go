package obfs

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
)

// TestObfsSelfLoop:NTR obfs 客户端(首写裹假 GET)↔ 服务端(读 GET 取体、回 101)经真 TCP,
// 验首包伪装 + 之后裸流双向自洽。
func TestObfsSelfLoop(t *testing.T) {
	built, err := Build(context.Background(), Config{Mode: "http", Host: "bing.com"}, nil)
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
		defer s.Close()
		// echo 两段:首段(裹在请求体)+ 后续裸段。
		buf := make([]byte, 256)
		for i := 0; i < 2; i++ {
			n, e := s.Read(buf)
			if e != nil {
				return
			}
			_, _ = s.Write(buf[:n])
		}
		time.Sleep(200 * time.Millisecond)
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

	// 首写(裹进 GET 体)+ 读回。
	if _, err := cs.Write([]byte("first-in-body")); err != nil {
		t.Fatalf("write1: %v", err)
	}
	got := make([]byte, len("first-in-body"))
	if _, err := io.ReadFull(cs, got); err != nil {
		t.Fatalf("read1: %v", err)
	}
	if string(got) != "first-in-body" {
		t.Fatalf("echo1 不符:%q", got)
	}
	// 后续裸写 + 读回。
	if _, err := cs.Write([]byte("second-raw")); err != nil {
		t.Fatalf("write2: %v", err)
	}
	got2 := make([]byte, len("second-raw"))
	if _, err := io.ReadFull(cs, got2); err != nil {
		t.Fatalf("read2: %v", err)
	}
	if string(got2) != "second-raw" {
		t.Fatalf("echo2 不符:%q", got2)
	}
}

type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

var _ link.Stream = connStream{}
