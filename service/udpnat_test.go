package service

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

type dgram struct {
	data []byte
	dst  addr.Socksaddr
}

// mockClient:模拟多目标客户端 PacketConn。ReadPacket 从 in 出包,反向 WritePacket 收进 out。
type mockClient struct {
	in   chan dgram
	out  chan dgram
	done chan struct{}
	once sync.Once
}

func (m *mockClient) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	select {
	case p := <-m.in:
		_, _ = b.Write(p.data)
		return p.dst, nil
	case <-m.done:
		return addr.Socksaddr{}, net.ErrClosed
	}
}
func (m *mockClient) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	select {
	case m.out <- dgram{append([]byte(nil), b.Bytes()...), dst}:
		return nil
	case <-m.done:
		return net.ErrClosed
	}
}
func (m *mockClient) Close() error                  { m.once.Do(func() { close(m.done) }); return nil }
func (m *mockClient) LocalAddr() net.Addr           { return nil }
func (m *mockClient) SetDeadline(t time.Time) error { return nil }
func (m *mockClient) Unwrap() any                   { return nil }

// echoConn:单目标出站 mock,写进即可读回(模拟目标回显)。
type echoConn struct {
	q    chan []byte
	done chan struct{}
	once sync.Once
}

func newEcho() *echoConn { return &echoConn{q: make(chan []byte, 8), done: make(chan struct{})} }
func (c *echoConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	select {
	case d := <-c.q:
		_, _ = b.Write(d)
		return addr.Socksaddr{}, nil
	case <-c.done:
		return addr.Socksaddr{}, net.ErrClosed
	}
}
func (c *echoConn) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error {
	select {
	case c.q <- append([]byte(nil), b.Bytes()...):
		return nil
	case <-c.done:
		return net.ErrClosed
	}
}
func (c *echoConn) Close() error                  { c.once.Do(func() { close(c.done) }); return nil }
func (c *echoConn) LocalAddr() net.Addr           { return nil }
func (c *echoConn) SetDeadline(t time.Time) error { return nil }
func (c *echoConn) Unwrap() any                   { return nil }

// echoOutbound:每 dst 一条 echoConn,记录见过的目标。
var _ endpoint.Outbound = (*echoOutbound)(nil)

type echoOutbound struct {
	mu      sync.Mutex
	targets map[string]int
}

func (o *echoOutbound) DialStream(context.Context, addr.Socksaddr) (link.Stream, error) {
	return nil, net.ErrClosed
}
func (o *echoOutbound) DialPacket(_ context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	o.mu.Lock()
	o.targets[dst.String()]++
	o.mu.Unlock()
	return newEcho(), nil
}

// TestUDPNATMultiTarget:两个不同目标的包各自建独立出站 + 回显按目标写回客户端(多目标 + 并发反向)。
func TestUDPNATMultiTarget(t *testing.T) {
	cli := &mockClient{in: make(chan dgram, 8), out: make(chan dgram, 8), done: make(chan struct{})}
	out := &echoOutbound{targets: map[string]int{}}
	go func() { _ = udpNAT(context.Background(), cli, StaticOutbound{Out: out}) }()

	d1 := addr.FromFqdn("a.example", 53)
	d2 := addr.FromFqdn("b.example", 5353)
	cli.in <- dgram{[]byte("to-a"), d1}
	cli.in <- dgram{[]byte("to-b"), d2}
	cli.in <- dgram{[]byte("to-a-again"), d1} // 同目标复用同一出站

	got := map[string]string{}
	for i := 0; i < 3; i++ {
		select {
		case r := <-cli.out:
			got[r.dst.String()] += string(r.data)
		case <-time.After(2 * time.Second):
			t.Fatalf("只收到 %d 个回显", i)
		}
	}
	if got["a.example:53"] != "to-ato-a-again" && got["a.example:53"] != "to-a-againto-a" {
		t.Fatalf("目标 a 回显错:%q", got["a.example:53"])
	}
	if got["b.example:5353"] != "to-b" {
		t.Fatalf("目标 b 回显错:%q", got["b.example:5353"])
	}
	cli.Close()
	out.mu.Lock()
	defer out.mu.Unlock()
	if out.targets["a.example:53"] != 1 || out.targets["b.example:5353"] != 1 {
		t.Fatalf("每目标应仅建 1 条出站:%v", out.targets)
	}
}
