package tls

import (
	"context"
	cryptotls "crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/core/link"
)

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

// tlsPair 用自签证书在回环 TCP 上完成 TLS 握手,返回客户端/服务端两条承载 stream。
func tlsPair(t *testing.T) (link.Stream, link.Stream) {
	t.Helper()
	tr, err := Build(context.Background(), Config{Insecure: true}, nil) // 留空证书→自签;客户端跳过校验
	if err != nil {
		t.Fatal(err)
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
	cs, err := trans.ClientWrap(ctx, pipeStream{c})
	if err != nil {
		t.Fatalf("ClientWrap: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("ServerWrap: %v", r.err)
	}
	return cs, r.s
}

// TestTLSRoundTrip:TLS 握手 + 明文双向直穿。
func TestTLSRoundTrip(t *testing.T) {
	cs, ss := tlsPair(t)
	go func() { _, _ = cs.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(ss, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q", buf)
	}
}

// TestTLSConnCarrier:tls stream 应暴露 link.TLSConnCarrier,且 TLSConn() 返回 *crypto/tls.Conn
// —— 这是 VLESS Vision 反射做 splice 的前提(sing-vmess/vless 的 tlsRegistry 认 *tls.Conn)。
func TestTLSConnCarrier(t *testing.T) {
	cs, ss := tlsPair(t)
	for name, s := range map[string]link.Stream{"client": cs, "server": ss} {
		carrier, ok := link.GetCapability[link.TLSConnCarrier](s)
		if !ok {
			t.Fatalf("%s: tls stream 未暴露 TLSConnCarrier", name)
		}
		if _, ok := carrier.TLSConn().(*cryptotls.Conn); !ok {
			t.Fatalf("%s: TLSConn() 应返回 *crypto/tls.Conn,得 %T", name, carrier.TLSConn())
		}
	}
}
