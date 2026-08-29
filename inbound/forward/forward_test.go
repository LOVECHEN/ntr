package forward

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

// echoPacket 是一条把写入原样回读的 link.PacketConn(模拟"上游 UDP 回显目标")。
type echoPacket struct {
	mu     sync.Mutex
	q      chan []byte
	closed chan struct{}
	once   sync.Once
}

func newEchoPacket() *echoPacket {
	return &echoPacket{q: make(chan []byte, 16), closed: make(chan struct{})}
}

func (e *echoPacket) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	select {
	case p := <-e.q:
		b.Reset()
		_, _ = b.Write(p)
		return addr.Socksaddr{}, nil
	case <-e.closed:
		return addr.Socksaddr{}, net.ErrClosed
	}
}

func (e *echoPacket) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error {
	p := make([]byte, len(b.Bytes()))
	copy(p, b.Bytes())
	select {
	case e.q <- p:
	case <-e.closed:
		return net.ErrClosed
	}
	return nil
}

func (e *echoPacket) Close() error {
	e.once.Do(func() { close(e.closed) })
	return nil
}
func (e *echoPacket) LocalAddr() net.Addr        { return &net.UDPAddr{} }
func (e *echoPacket) SetDeadline(time.Time) error { return nil }
func (e *echoPacket) Unwrap() any                 { return nil }

// fakeOut 是只服务 UDP 的假出站:DialPacket 返回一条 echoPacket。
type fakeOut struct{ pc *echoPacket }

func (f *fakeOut) DialStream(context.Context, addr.Socksaddr) (link.Stream, error) {
	return nil, net.ErrClosed
}
func (f *fakeOut) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return f.pc, nil
}

// TestNATRoundtrip:Dispatch 建流 → payload 经 out(echo)回来 → sendBack 收到相同字节;
// 同 key 再来复用同一流(不新建)。
func TestNATRoundtrip(t *testing.T) {
	out := &fakeOut{pc: newEchoPacket()}
	nat := NewNAT(2 * time.Second)
	got := make(chan []byte, 4)

	var opens int
	var mu sync.Mutex
	open := func() (func([]byte) error, func(), error) {
		mu.Lock()
		opens++
		mu.Unlock()
		return func(p []byte) error {
			cp := make([]byte, len(p))
			copy(cp, p)
			got <- cp
			return nil
		}, nil, nil
	}

	dst := addr.FromFqdn("echo.test", 5353)
	nat.Dispatch(context.Background(), out, "k", dst, &net.UDPAddr{}, open, []byte("hello"))

	select {
	case p := <-got:
		if string(p) != "hello" {
			t.Fatalf("回读不符:%q", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("超时:未收到 echo 回包")
	}

	// 同 key 复用:不应再 open。
	nat.Dispatch(context.Background(), out, "k", dst, &net.UDPAddr{}, open, []byte("world"))
	select {
	case p := <-got:
		if string(p) != "world" {
			t.Fatalf("第二包回读不符:%q", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("超时:第二包未回")
	}
	mu.Lock()
	defer mu.Unlock()
	if opens != 1 {
		t.Fatalf("期望仅 open 一次(同 key 复用),实际 %d", opens)
	}
}
