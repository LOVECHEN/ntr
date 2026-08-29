package vmess

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
)

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

// TestVMessRoundTrip:同一 UUID 的 Proxy 兼作客户端/服务端,客户端写请求头 → 服务端解出目标 +
// 捕获内层流,payload 双向直穿(隔离验证 VMess codec 经 NTR 插件适配后自洽)。
func TestVMessRoundTrip(t *testing.T) {
	const uuid = "11111111-1111-1111-1111-111111111111"
	p, err := Build(context.Background(), Config{UUID: uuid, Security: "auto"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pr := p.(*Proxy)

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()
	dst := addr.FromFqdn("target.example", 443)

	errc := make(chan error, 1)
	go func() {
		cs, err := pr.ClientHandshake(ctx, pipeStream{c}, nil, dst)
		if err != nil {
			errc <- err
			return
		}
		if _, err := cs.Write([]byte("REQ")); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(cs, buf); err != nil {
			errc <- err
			return
		}
		if string(buf) != "RESP" {
			errc <- io.ErrUnexpectedEOF
			return
		}
		errc <- nil
	}()

	ss, req, err := pr.ServerHandshake(ctx, pipeStream{s}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst.String() != "target.example:443" {
		t.Fatalf("dst = %s, want target.example:443", req.Dst.String())
	}
	pl := make([]byte, 3)
	if _, err := io.ReadFull(ss, pl); err != nil {
		t.Fatal(err)
	}
	if string(pl) != "REQ" {
		t.Fatalf("payload = %q", pl)
	}
	if _, err := ss.Write([]byte("RESP")); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}
