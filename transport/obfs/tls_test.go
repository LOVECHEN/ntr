package obfs

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestObfsTLSSelfLoop:NTR obfs(mode=tls)客户端(首写发假 ClientHello、数据藏 session-ticket)↔
// 服务端(读 ticket 数据、回假 ServerHello,之后 app-data 记录)经真 TCP,验双向自洽 + 大包分片。
func TestObfsTLSSelfLoop(t *testing.T) {
	built, err := Build(context.Background(), Config{Mode: "tls", Host: "bing.com"}, nil)
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
		// echo:把每次读到的原样写回(io.Copy 直到对端半关)。
		_, _ = io.Copy(s, s)
		time.Sleep(100 * time.Millisecond)
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

	// 首段(藏 session-ticket)。
	first := []byte("first-in-session-ticket")
	if _, err := cs.Write(first); err != nil {
		t.Fatalf("write1: %v", err)
	}
	got := make([]byte, len(first))
	if _, err := io.ReadFull(cs, got); err != nil {
		t.Fatalf("read1: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("echo1 不符:%q", got)
	}

	// 后续 app-data 记录(含一段 >16KiB 触发分片)。
	big := bytes.Repeat([]byte("X"), 40000)
	if _, err := cs.Write(big); err != nil {
		t.Fatalf("write2: %v", err)
	}
	got2 := make([]byte, len(big))
	if _, err := io.ReadFull(cs, got2); err != nil {
		t.Fatalf("read2: %v", err)
	}
	if !bytes.Equal(got2, big) {
		t.Fatalf("echo2(大包)不符:len=%d", len(got2))
	}
}
