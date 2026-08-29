package mixed

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
)

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

type authStub struct{}

func (authStub) Auth(string, []byte) (cred.Ref, bool) { return cred.Ref{}, false }

func newMixed(t *testing.T) *Proxy {
	t.Helper()
	v, err := Build(context.Background(), Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return v.(*Proxy)
}

// handshake 在 pipe 上跑一次 mixed 握手,client 回调负责扮演客户端。
func handshake(t *testing.T, client func(c net.Conn)) (dst string, network endpoint.Network) {
	t.Helper()
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	p := newMixed(t)

	type res struct {
		dst string
		net endpoint.Network
		err error
	}
	done := make(chan res, 1)
	go func() {
		_, rq, err := p.ServerHandshake(context.Background(), pipeStream{srv}, authStub{})
		if err != nil {
			done <- res{err: err}
			return
		}
		done <- res{dst: rq.Dst.String(), net: rq.Network}
	}()
	go client(cli)

	r := <-done
	if r.err != nil {
		t.Fatalf("握手失败:%v", r.err)
	}
	return r.dst, r.net
}

// TestMixedSocks5:首字节 0x05 → 分派给 socks5。
func TestMixedSocks5(t *testing.T) {
	dst, nw := handshake(t, func(c net.Conn) {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00}) // 问候
		_, _ = io.ReadFull(c, make([]byte, 2))   // 方法选择应答
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB})
		_, _ = io.ReadFull(c, make([]byte, 10)) // socks5 应答,必须读掉防死锁
	})
	if dst != "93.184.216.34:443" || nw != endpoint.NetworkTCP {
		t.Fatalf("socks5 分派错:dst=%s net=%v", dst, nw)
	}
}

// TestMixedSocks4a:首字节 0x04 → 分派给 socks4a(验证 v4 也走 socks 分支)。
func TestMixedSocks4a(t *testing.T) {
	dst, _ := handshake(t, func(c net.Conn) {
		var b bytes.Buffer
		b.WriteByte(0x04)
		b.WriteByte(0x01) // CONNECT
		var pt [2]byte
		binary.BigEndian.PutUint16(pt[:], 443)
		b.Write(pt[:])
		b.Write([]byte{0, 0, 0, 1}) // SOCKS4a 标记
		b.WriteByte(0)              // 空 USERID
		b.WriteString("example.com")
		b.WriteByte(0)
		_, _ = c.Write(b.Bytes())
		_, _ = io.ReadFull(c, make([]byte, 8)) // socks4 应答
	})
	if dst != "example.com:443" {
		t.Fatalf("socks4a 分派错:%s", dst)
	}
}

// TestMixedHTTPConnect:首字节 'C' → 分派给 http(CONNECT 隧道)。
func TestMixedHTTPConnect(t *testing.T) {
	dst, nw := handshake(t, func(c net.Conn) {
		_, _ = c.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
		_, _ = io.ReadFull(c, make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n")))
	})
	if dst != "example.com:443" || nw != endpoint.NetworkTCP {
		t.Fatalf("http CONNECT 分派错:dst=%s net=%v", dst, nw)
	}
}

// TestMixedHTTPPlain:首字节 'G' → 分派给 http(明文转发)。
func TestMixedHTTPPlain(t *testing.T) {
	dst, _ := handshake(t, func(c net.Conn) {
		_, _ = c.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	})
	if dst != "example.com:80" {
		t.Fatalf("http 明文分派错:%s", dst)
	}
}

// TestMixedEmptyStream:未发任何字节应报错而非 panic/挂起。
func TestMixedEmptyStream(t *testing.T) {
	cli, srv := net.Pipe()
	p := newMixed(t)
	errc := make(chan error, 1)
	go func() {
		_, _, err := p.ServerHandshake(context.Background(), pipeStream{srv}, authStub{})
		errc <- err
	}()
	_ = cli.Close() // 立刻关闭,不发任何数据
	if err := <-errc; err == nil {
		t.Fatal("空流应报错")
	}
	_ = srv.Close()
}
