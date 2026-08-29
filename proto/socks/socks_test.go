package socks

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/core/cred"
)

// TestServerHandshakeConnect:最小 SOCKS5 客户端跑 no-auth 协商 + CONNECT 请求,
// 服务端解出 dst、回 success、之后 payload 直通。
func TestServerHandshakeConnect(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()

	errc := make(chan error, 1)
	go func() {
		// 问候:VER=5, NMETHODS=1, no-auth
		if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			errc <- err
			return
		}
		sel := make([]byte, 2)
		if _, err := io.ReadFull(c, sel); err != nil {
			errc <- err
			return
		}
		if sel[0] != 0x05 || sel[1] != 0x00 {
			errc <- errBad("method selection")
			return
		}
		// 请求:CONNECT example.com:443
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}
		req = append(req, "example.com"...)
		req = append(req, 0x01, 0xBB)
		if _, err := c.Write(req); err != nil {
			errc <- err
			return
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(c, reply); err != nil {
			errc <- err
			return
		}
		if reply[0] != 0x05 || reply[1] != 0x00 {
			errc <- errBad("reply")
			return
		}
		if _, err := c.Write([]byte("PING")); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			errc <- err
			return
		}
		if string(buf) != "PONG" {
			errc <- errBad("echo")
			return
		}
		errc <- nil
	}()

	p := &Proxy{}
	ss, req, err := p.ServerHandshake(ctx, pipeStream{s}, denyAuth{})
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst.String() != "example.com:443" {
		t.Fatalf("dst = %s", req.Dst.String())
	}
	if req.Command != CmdConnect {
		t.Fatalf("cmd = %d", req.Command)
	}
	if req.Cred.ID != cred.Ambient {
		t.Fatalf("no-auth 本地入站应归 Ambient,得 %d", req.Cred.ID)
	}
	pl := make([]byte, 4)
	if _, err := io.ReadFull(ss, pl); err != nil {
		t.Fatal(err)
	}
	if string(pl) != "PING" {
		t.Fatalf("payload = %q", pl)
	}
	if _, err := ss.Write([]byte("PONG")); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

// denyAuth 恒不匹配 → socks 回落 Ambient。
type denyAuth struct{}

func (denyAuth) Auth(string, []byte) (cred.Ref, bool) { return cred.Ref{}, false }

type errBad string

func (e errBad) Error() string { return "socks test: bad " + string(e) }
