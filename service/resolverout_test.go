package service

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var errSentinel = errors.New("sentinel")

// recResolver 记录 ResolveConn 收到的 dst/network,返回预置出站。
type recResolver struct {
	dst addr.Socksaddr
	net string
	out endpoint.Outbound
}

func (r *recResolver) Resolve(ctx context.Context, dst addr.Socksaddr) (endpoint.Outbound, error) {
	return r.ResolveConn(ctx, dst, netip.AddrPort{}, "tcp")
}
func (r *recResolver) ResolveConn(_ context.Context, dst addr.Socksaddr, _ netip.AddrPort, network string) (endpoint.Outbound, error) {
	r.dst = dst
	r.net = network
	return r.out, nil
}

// recOutbound 记录 Dial 收到的 dst,返回 sentinel(不需真连接)。
type recOutbound struct{ streamDst, packetDst addr.Socksaddr }

func (o *recOutbound) DialStream(_ context.Context, dst addr.Socksaddr) (link.Stream, error) {
	o.streamDst = dst
	return nil, errSentinel
}
func (o *recOutbound) DialPacket(_ context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	o.packetDst = dst
	return nil, errSentinel
}

// TestResolverOutboundDispatch:适配器每次拨号按 dst 现查 resolver 再委托,且 TCP/UDP 带对 network。
func TestResolverOutboundDispatch(t *testing.T) {
	oo := &recOutbound{}
	rr := &recResolver{out: oo}
	ro := NewResolverOutbound(rr)

	dstT := addr.FromFqdn("tcp.example.com", 443)
	if _, err := ro.DialStream(context.Background(), dstT); err != errSentinel {
		t.Fatalf("DialStream err=%v 期望 sentinel(证已委托到 out)", err)
	}
	if rr.dst != dstT || rr.net != "tcp" {
		t.Errorf("DialStream 传给 resolver dst=%v net=%q 期望 %v/tcp", rr.dst, rr.net, dstT)
	}
	if oo.streamDst != dstT {
		t.Errorf("委托 out.DialStream dst=%v 期望 %v", oo.streamDst, dstT)
	}

	dstU := addr.FromFqdn("udp.example.com", 53)
	if _, err := ro.DialPacket(context.Background(), dstU); err != errSentinel {
		t.Fatalf("DialPacket err=%v 期望 sentinel", err)
	}
	if rr.dst != dstU || rr.net != "udp" {
		t.Errorf("DialPacket 传给 resolver dst=%v net=%q 期望 %v/udp", rr.dst, rr.net, dstU)
	}
	if oo.packetDst != dstU {
		t.Errorf("委托 out.DialPacket dst=%v 期望 %v", oo.packetDst, dstU)
	}
}
