package dns

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/route"
)

// cannedResponse 造一份 example.com A=1.2.3.4 TTL=300 的应答(txid 由 setTxID 对齐查询)。
func cannedResponse(id uint16) []byte {
	name, _ := dnsmessage.NewName("example.com.")
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
			Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
		}},
	}
	raw, _ := m.Pack()
	return raw
}

// fakeUpstream 是只服务 UDP 的假出站:DialPacket 返回一条按查询 txid 回一份 canned 应答的 PacketConn。
type fakeUpstream struct{ calls *atomic.Int64 }

func (f fakeUpstream) DialStream(context.Context, addr.Socksaddr) (link.Stream, error) {
	return nil, context.Canceled
}
func (f fakeUpstream) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	f.calls.Add(1)
	return &fakePC{resp: make(chan []byte, 1)}, nil
}

type fakePC struct{ resp chan []byte }

func (c *fakePC) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error {
	id := binary.BigEndian.Uint16(b.Bytes()[0:2])
	c.resp <- cannedResponse(id)
	return nil
}
func (c *fakePC) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	r := <-c.resp
	b.Reset()
	_, _ = b.Write(r)
	return addr.Socksaddr{}, nil
}
func (c *fakePC) Close() error                  { return nil }
func (c *fakePC) LocalAddr() net.Addr           { return nil }
func (c *fakePC) SetDeadline(time.Time) error   { return nil }
func (c *fakePC) Unwrap() any                   { return nil }

// TestExchangeAndCache:Exchange 解出应答;同名再查命中缓存(上游只被拨一次)。
func TestExchangeAndCache(t *testing.T) {
	var calls atomic.Int64
	r, err := New([]Nameserver{{Tag: "fake", Address: "udp://1.1.1.1:53", Detour: fakeUpstream{calls: &calls}}}, nil, "race", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := buildQuery("example.com", dnsmessage.TypeA)

	resp, err := r.Exchange(context.Background(), &route.Message{Raw: q})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	na, ok := parseAddrs(resp.Raw)
	if !ok || len(na) != 1 || netip.AddrFrom4(na[0].a4) != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("应答解析错:%+v ok=%v", na, ok)
	}

	// 第二次同名:应命中缓存,不再拨上游。
	if _, err := r.Exchange(context.Background(), &route.Message{Raw: q}); err != nil {
		t.Fatalf("Exchange2: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("期望上游只拨 1 次(第二次命中缓存),实际 %d", got)
	}
}

// TestLookup:Lookup 返回 A 地址。
func TestLookup(t *testing.T) {
	var calls atomic.Int64
	r, _ := New([]Nameserver{{Tag: "fake", Address: "udp://1.1.1.1:53", Detour: fakeUpstream{calls: &calls}}}, nil, "race", nil, nil)
	addrs, err := r.Lookup(context.Background(), "example.com", route.StratV4Only)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("Lookup 结果错:%v", addrs)
	}
}
