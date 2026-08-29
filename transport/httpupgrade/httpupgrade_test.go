package httpupgrade

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/core/link"
)

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

func wrapPair(t *testing.T) (link.Stream, link.Stream, func()) {
	t.Helper()
	c, s := net.Pipe()
	ctx := context.Background()
	tr, err := Build(ctx, Config{Path: "/cdn", Host: "h.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	trans := tr.(*Transport)
	type res struct {
		ss  link.Stream
		err error
	}
	ch := make(chan res, 1)
	go func() {
		ss, err := trans.ServerWrap(ctx, pipeStream{s})
		ch <- res{ss, err}
	}()
	cs, err := trans.ClientWrap(ctx, pipeStream{c})
	if err != nil {
		t.Fatalf("ClientWrap: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("ServerWrap: %v", r.err)
	}
	return cs, r.ss, func() { c.Close(); s.Close() }
}

// TestRoundTrip:握手后裸流双向直穿,含大 payload(验证无分帧、bufio 预读接回正确)。
func TestRoundTrip(t *testing.T) {
	cs, ss, done := wrapPair(t)
	defer done()
	want := bytes.Repeat([]byte("payload-"), 10000) // 80KB
	go func() {
		if _, err := cs.Write(want); err != nil {
			t.Errorf("client write: %v", err)
		}
	}()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(ss, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("c→s 不一致")
	}
	// 反向
	want2 := []byte("server-response-bytes")
	go func() { ss.Write(want2) }()
	got2 := make([]byte, len(want2))
	if _, err := io.ReadFull(cs, got2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, want2) {
		t.Fatal("s→c 不一致")
	}
}

// TestRejectRealWebSocket:带 Sec-WebSocket-Key 的真 WS 请求应被 httpupgrade 服务端拒绝。
func TestRejectRealWebSocket(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()
	go func() {
		_, _ = c.Write([]byte("GET /cdn HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\n\r\n"))
	}()
	tr, _ := Build(ctx, Config{Path: "/cdn", Host: "h"}, nil)
	if _, err := tr.(*Transport).ServerWrap(ctx, pipeStream{s}); err == nil {
		t.Fatal("真 WebSocket 请求应被 httpupgrade 服务端拒绝")
	}
}
