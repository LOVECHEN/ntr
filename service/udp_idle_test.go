package service

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

// idleClient 是尊重 SetDeadline 的客户端 mock:ReadPacket 在 deadline 到期且无新包时返回 deadline 错。
type idleClient struct {
	in       chan dgram
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
}

func (m *idleClient) SetDeadline(t time.Time) error {
	m.mu.Lock()
	m.deadline = t
	m.mu.Unlock()
	return nil
}
func (m *idleClient) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	m.mu.Lock()
	dl := m.deadline
	m.mu.Unlock()
	var timer <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return addr.Socksaddr{}, os.ErrDeadlineExceeded
		}
		tm := time.NewTimer(d)
		defer tm.Stop()
		timer = tm.C
	}
	select {
	case p := <-m.in:
		_, _ = b.Write(p.data)
		return p.dst, nil
	case <-timer:
		return addr.Socksaddr{}, os.ErrDeadlineExceeded
	case <-m.done:
		return addr.Socksaddr{}, net.ErrClosed
	}
}
func (m *idleClient) WritePacket(*buf.Buffer, addr.Socksaddr) error { return nil }
func (m *idleClient) Close() error                                  { m.once.Do(func() { close(m.done) }); return nil }
func (m *idleClient) LocalAddr() net.Addr                           { return nil }
func (m *idleClient) Unwrap() any                                   { return nil }

// recOut 记录建出的 echoConn,供断言 closeAll 关掉了它们。
type recOut struct {
	mu    sync.Mutex
	conns []*echoConn
}

func (o *recOut) DialStream(context.Context, addr.Socksaddr) (link.Stream, error) {
	return nil, net.ErrClosed
}
func (o *recOut) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	c := newEcho()
	o.mu.Lock()
	o.conns = append(o.conns, c)
	o.mu.Unlock()
	return c, nil
}

var _ endpoint.Outbound = (*recOut)(nil)

// TestUDPNATIdle 守 reaper Seam 4(§10):UDP assoc 客户端静默超 udpIdle → udpNAT 整关返回,
// closeAll 关掉全部出站。
func TestUDPNATIdle(t *testing.T) {
	SetUDPIdle(120 * time.Millisecond)
	defer SetUDPIdle(0)

	cli := &idleClient{in: make(chan dgram, 4), done: make(chan struct{})}
	out := &recOut{}
	done := make(chan error, 1)
	go func() { done <- udpNAT(context.Background(), cli, StaticOutbound{Out: out}) }()

	cli.in <- dgram{[]byte("hi"), addr.FromFqdn("a.example", 53)} // 建一条 target
	time.Sleep(20 * time.Millisecond)                             // 让 target 建起来
	// 此后客户端静默 → 过 udpIdle 后主循环 ReadPacket 超时 → udpNAT 返回。
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("udpNAT 应因 idle 超时返回错误")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UDP idle 未生效:udpNAT 在客户端静默后未返回(assoc 永久钉住)")
	}
	// closeAll 应关掉建过的出站。
	out.mu.Lock()
	conns := out.conns
	out.mu.Unlock()
	if len(conns) == 0 {
		t.Fatal("未建任何出站(测试前提不成立)")
	}
	for i, c := range conns {
		select {
		case <-c.done: // Close 关掉 done
		case <-time.After(time.Second):
			t.Fatalf("出站 #%d 未被 closeAll 关闭", i)
		}
	}
}
