package vmess

import (
	"context"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
)

// TestVMessUDPRoundTrip:同 UUID 的 Proxy 兼作客户端/服务端,客户端 DialPacketConn 发起 VMess UDP
// 会话(Command=UDP),服务端捕获 sing PacketConn 并经 ServerPacketConn 适配;datagram 双向直穿
// (隔离验证 sing-vmess UDP 经字节切片桥接后自洽:ReadFrom/WriteTo 内部自管 headroom)。
func TestVMessUDPRoundTrip(t *testing.T) {
	const uuid = "22222222-2222-2222-2222-222222222222"
	p, err := Build(context.Background(), Config{UUID: uuid, Security: "auto"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pr := p.(*Proxy)

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()
	dst := addr.FromFqdn("dns.example", 53)

	errc := make(chan error, 1)
	go func() {
		pc, err := pr.DialPacketConn(ctx, pipeStream{c}, nil, dst)
		if err != nil {
			errc <- err
			return
		}
		wb := buf.New()
		_, _ = wb.Write([]byte("PING"))
		if err := pc.WritePacket(wb, dst); err != nil {
			wb.Release()
			errc <- err
			return
		}
		wb.Release()
		rb := buf.New()
		defer rb.Release()
		if _, err := pc.ReadPacket(rb); err != nil {
			errc <- err
			return
		}
		if string(rb.Bytes()) != "PONG" {
			errc <- errUnexpected(rb.Bytes())
			return
		}
		errc <- nil
	}()

	ss, req, err := pr.ServerHandshake(ctx, pipeStream{s}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Network != endpoint.NetworkUDP {
		t.Fatalf("network = %v, want UDP", req.Network)
	}
	if req.Dst.String() != "dns.example:53" {
		t.Fatalf("dst = %s, want dns.example:53", req.Dst.String())
	}
	spc, err := pr.ServerPacketConn(ss, req.Dst)
	if err != nil {
		t.Fatal(err)
	}
	rb := buf.New()
	defer rb.Release()
	rdst, err := spc.ReadPacket(rb)
	if err != nil {
		t.Fatal(err)
	}
	if string(rb.Bytes()) != "PING" {
		t.Fatalf("payload = %q, want PING", rb.Bytes())
	}
	if rdst.String() != "dns.example:53" {
		t.Fatalf("read dst = %s, want dns.example:53", rdst.String())
	}
	wb := buf.New()
	_, _ = wb.Write([]byte("PONG"))
	if err := spc.WritePacket(wb, rdst); err != nil {
		wb.Release()
		t.Fatal(err)
	}
	wb.Release()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

type unexpectedErr []byte

func (e unexpectedErr) Error() string { return "unexpected payload: " + string(e) }
func errUnexpected(b []byte) error    { return unexpectedErr(append([]byte(nil), b...)) }
