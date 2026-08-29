package trojan

import (
	"context"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
)

// TestTrojanUDPRoundTrip:客户端 DialPacketConn 写 UDP 请求头 + 两个不同目标的包 → 服务端
// ServerHandshake 识别 UDP + ServerPacketConn 解出各包地址(多目标);反向包也带回目标。
func TestTrojanUDPRoundTrip(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()
	dst1 := addr.FromFqdn("a.example", 53)
	dst2 := addr.FromFqdn("b.example", 5353)
	auth := testAuth{hash: string(Key(testPassword)), ref: cred.Ref{ID: cred.Ambient}}

	errc := make(chan error, 1)
	go func() {
		p := &Proxy{}
		cpc, err := p.DialPacketConn(ctx, pipeStream{c}, []byte(testPassword), dst1)
		if err != nil {
			errc <- err
			return
		}
		b := buf.New()
		_, _ = b.Write([]byte("query-one"))
		if err := cpc.WritePacket(b, dst1); err != nil {
			errc <- err
			return
		}
		b.Release()
		b2 := buf.New()
		_, _ = b2.Write([]byte("q2"))
		if err := cpc.WritePacket(b2, dst2); err != nil {
			errc <- err
			return
		}
		b2.Release()
		rb := buf.New()
		defer rb.Release()
		d, err := cpc.ReadPacket(rb)
		if err != nil {
			errc <- err
			return
		}
		if string(rb.Bytes()) != "reply" || d.String() != "a.example:53" {
			errc <- errUDPTooLarge // 复用一个 error 值,内容不重要
			return
		}
		errc <- nil
	}()

	p := &Proxy{}
	ss, req, err := p.ServerHandshake(ctx, pipeStream{s}, auth)
	if err != nil {
		t.Fatal(err)
	}
	if req.Network != endpoint.NetworkUDP {
		t.Fatalf("Network = %v, want UDP", req.Network)
	}
	spc, err := p.ServerPacketConn(ss, req.Dst)
	if err != nil {
		t.Fatal(err)
	}
	b := buf.New()
	defer b.Release()
	d1, err := spc.ReadPacket(b)
	if err != nil {
		t.Fatal(err)
	}
	if d1.String() != "a.example:53" || string(b.Bytes()) != "query-one" {
		t.Fatalf("包1:%s / %q", d1.String(), b.Bytes())
	}
	b.Reset()
	d2, err := spc.ReadPacket(b)
	if err != nil {
		t.Fatal(err)
	}
	if d2.String() != "b.example:5353" || string(b.Bytes()) != "q2" {
		t.Fatalf("包2(多目标):%s / %q", d2.String(), b.Bytes())
	}
	rb := buf.New()
	_, _ = rb.Write([]byte("reply"))
	if err := spc.WritePacket(rb, dst1); err != nil {
		t.Fatal(err)
	}
	rb.Release()
	if err := <-errc; err != nil {
		t.Fatalf("客户端:%v", err)
	}
}
