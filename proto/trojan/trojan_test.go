package trojan

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
)

const testPassword = "hunter2-correct-horse"

// TestServerClientHandshake:客户端写头 → 服务端解出 dst + 按 hash 鉴权到具名凭据,
// 之后 payload 直接双向流(裸管道,不含 TLS —— 隔离验证 trojan 头 codec)。
func TestServerClientHandshake(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()

	dst := addr.FromFqdn("target.example", 8443)
	userRef := cred.Ref{ID: cred.UserBase + 3}
	auth := testAuth{hash: string(Key(testPassword)), ref: userRef}

	errc := make(chan error, 1)
	go func() {
		p := &Proxy{}
		cs, err := p.ClientHandshake(ctx, pipeStream{c}, []byte(testPassword), dst)
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

	p := &Proxy{}
	ss, req, err := p.ServerHandshake(ctx, pipeStream{s}, auth)
	if err != nil {
		t.Fatal(err)
	}
	if req.Cred.ID != userRef.ID {
		t.Fatalf("cred = %d, want %d", req.Cred.ID, userRef.ID)
	}
	if req.Dst.String() != "target.example:8443" {
		t.Fatalf("dst = %s", req.Dst.String())
	}
	if req.Command != CmdConnect {
		t.Fatalf("cmd = %d", req.Command)
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

// TestUnknownUserRejected:错 password 的 hash 不在表 → 服务端响亮 ErrAuth。
func TestUnknownUserRejected(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()

	go func() {
		p := &Proxy{}
		_, _ = p.ClientHandshake(ctx, pipeStream{c}, []byte("wrong-password"), addr.FromFqdn("x", 1))
	}()

	p := &Proxy{}
	if _, _, err := p.ServerHandshake(ctx, pipeStream{s}, testAuth{}); err == nil {
		t.Fatal("未知用户应被响亮拒绝")
	}
}

func TestIPv4AddrRoundTrip(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()
	dst := addr.Socksaddr{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}
	auth := testAuth{hash: string(Key(testPassword)), ref: cred.Ref{ID: cred.Ambient}}

	go func() {
		p := &Proxy{}
		_, _ = p.ClientHandshake(ctx, pipeStream{c}, []byte(testPassword), dst)
	}()
	p := &Proxy{}
	_, req, err := p.ServerHandshake(ctx, pipeStream{s}, auth)
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst.String() != "1.2.3.4:443" {
		t.Fatalf("dst = %s", req.Dst.String())
	}
}

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

type testAuth struct {
	hash string
	ref  cred.Ref
}

func (a testAuth) Auth(scheme string, key []byte) (cred.Ref, bool) {
	if scheme == "trojan" && string(key) == a.hash && a.hash != "" {
		return a.ref, true
	}
	return cred.Ref{}, false
}
