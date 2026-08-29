package shadowsocks

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
)

// key16 是 aes-128-gcm 的 16 字节 base64 密钥。
var key16 = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))

func buildProxy(t *testing.T) *Proxy {
	t.Helper()
	built, err := Build(context.Background(), Config{Method: defaultMethod, Password: key16}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return built.(*Proxy)
}

// TestShadowsocksRoundTrip:SS2022 client ↔ server 往返(请求头解出 dst + 双向 payload)。
func TestShadowsocksRoundTrip(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()
	p := buildProxy(t)
	dst := addr.FromFqdn("example.com", 443)

	errc := make(chan error, 1)
	go func() {
		cs, err := p.ClientHandshake(ctx, pipeStream{c}, nil, dst)
		if err != nil {
			errc <- err
			return
		}
		if _, err := cs.Write([]byte("hello ss2022")); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, len("ack ss2022"))
		if _, err := io.ReadFull(cs, buf); err != nil {
			errc <- err
			return
		}
		if string(buf) != "ack ss2022" {
			errc <- io.ErrUnexpectedEOF
			return
		}
		errc <- nil
	}()

	ss, req, err := p.ServerHandshake(ctx, pipeStream{s}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst.String() != "example.com:443" {
		t.Fatalf("server dst = %s", req.Dst.String())
	}
	pl := make([]byte, len("hello ss2022"))
	if _, err := io.ReadFull(ss, pl); err != nil {
		t.Fatal(err)
	}
	if string(pl) != "hello ss2022" {
		t.Fatalf("payload = %q", pl)
	}
	if _, err := ss.Write([]byte("ack ss2022")); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }
