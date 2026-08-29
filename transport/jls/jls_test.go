package jls

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
)

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

// jlsPair 用共享 PSK 在回环 TCP 上完成 JLS 握手,返回客户端/服务端两条承载 stream。
func jlsPair(t *testing.T, cfg Config) (link.Stream, link.Stream, error) {
	t.Helper()
	tr, err := Build(context.Background(), cfg, nil)
	if err != nil {
		return nil, nil, err
	}
	trans := tr.(*Transport)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx := context.Background()
	type res struct {
		s   link.Stream
		err error
	}
	ch := make(chan res, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- res{nil, err}
			return
		}
		s, err := trans.ServerWrap(ctx, pipeStream{conn})
		ch <- res{s, err}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cs, cerr := trans.ClientWrap(ctx, pipeStream{c})
	r := <-ch
	if cerr != nil {
		return nil, nil, cerr
	}
	if r.err != nil {
		return nil, nil, r.err
	}
	return cs, r.s, nil
}

// TestJLSRoundTrip:合法 PSK 双端 JLS 握手 + 明文双向直穿。
func TestJLSRoundTrip(t *testing.T) {
	cs, ss, err := jlsPair(t, Config{Username: "user1", Password: "pass1", Dest: "example.com:443"})
	if err != nil {
		t.Fatalf("JLS 握手: %v", err)
	}
	go func() { _, _ = cs.Write([]byte("ping-jls")) }()
	buf := make([]byte, 8)
	if _, err := io.ReadFull(ss, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping-jls" {
		t.Fatalf("got %q", buf)
	}
	// 反向
	go func() { _, _ = ss.Write([]byte("pong-jls")) }()
	if _, err := io.ReadFull(cs, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong-jls" {
		t.Fatalf("reverse got %q", buf)
	}
}

// TestJLSWrongPSK:PSK 不匹配 → 双端都不得静默认证通过(不产生可用 JLS 隧道)。
// ★注:JLS 无 fallback relay 时,错 PSK 会让双方互等 JLS 确认而阻塞,须靠握手 deadline 兜底 ——
// 故此处用带超时的 ctx(生产由入站握手超时提供),验证「错 PSK 不静默成功」而非「立即报错」。
// 完整的抗探测回落(错 PSK → 转发到真站)是后续增量(见 jls.go 包注)。
func TestJLSWrongPSK(t *testing.T) {
	trS, _ := Build(context.Background(), Config{Username: "u", Password: "right", Dest: "example.com:443"}, nil)
	trC, _ := Build(context.Background(), Config{Username: "u", Password: "wrong", Dest: "example.com:443"}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	srvOK := make(chan bool, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvOK <- false
			return
		}
		s, err := trS.(*Transport).ServerWrap(ctx, pipeStream{conn})
		if err == nil {
			_ = s.(*stream).Close()
			srvOK <- true
			return
		}
		srvOK <- false
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if s, err := trC.(*Transport).ClientWrap(ctx, pipeStream{c}); err == nil {
		_ = s.(*stream).Close()
		t.Errorf("客户端不应对错 PSK 认证通过")
	}
	if <-srvOK {
		t.Errorf("服务端不应对错 PSK 客户端认证通过")
	}
}
