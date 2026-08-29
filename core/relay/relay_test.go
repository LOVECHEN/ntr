package relay

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
)

// pipeStream 把 net.Conn 抬成 link.Stream。
type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

// TestRelayBidirectional:Relay(a,b) 在 a、b 间双向搬字节 —— 写 a 的对端能从 b 的对端读到,反之亦然。
func TestRelayBidirectional(t *testing.T) {
	aP, a := net.Pipe()
	bP, b := net.Pipe()
	defer aP.Close()
	defer bP.Close()

	done := make(chan error, 1)
	go func() { done <- Relay(pipeStream{a}, pipeStream{b}) }()

	// aP → (a→b) → bP
	go func() { _, _ = aP.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(bP, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("a→b = %q, want ping", buf)
	}

	// bP → (b→a) → aP
	go func() { _, _ = bP.Write([]byte("pong")) }()
	buf2 := make([]byte, 4)
	if _, err := io.ReadFull(aP, buf2); err != nil {
		t.Fatal(err)
	}
	if string(buf2) != "pong" {
		t.Fatalf("b→a = %q, want pong", buf2)
	}
}

// TestRelayClosePropagatesNoHang:任一端关闭后,Relay 必须收尾返回(关两端 + 等另一方向 goroutine),
// 不挂起、不泄漏 —— 这是审计时声称的"不泄漏 goroutine",此处用超时坐实。
func TestRelayClosePropagatesNoHang(t *testing.T) {
	aP, a := net.Pipe()
	bP, b := net.Pipe()
	defer bP.Close()

	done := make(chan error, 1)
	go func() { done <- Relay(pipeStream{a}, pipeStream{b}) }()

	// 关掉 a 的对端 → a 读到 EOF → Relay 关两端 → b→a 方向也结束 → Relay 返回。
	aP.Close()

	select {
	case <-done:
		// Relay 返回即证明两个 copy goroutine 都收尾了(Relay 末尾 <-errc 等了第二个)。
	case <-time.After(3 * time.Second):
		t.Fatal("一端关闭后 Relay 未返回(goroutine 泄漏/挂起)")
	}
}

// TestRelayLargeStream:大流量双向搬运正确(池化缓冲多轮复用,验证无错位/截断)。
func TestRelayLargeStream(t *testing.T) {
	aP, a := net.Pipe()
	bP, b := net.Pipe()
	defer aP.Close()
	defer bP.Close()
	go func() { _ = Relay(pipeStream{a}, pipeStream{b}) }()

	const n = 512 * 1024
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	go func() { _, _ = aP.Write(payload) }()
	got := make([]byte, n)
	if _, err := io.ReadFull(bP, got); err != nil {
		t.Fatal(err)
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("字节 %d 不一致", i)
		}
	}
}

// ---------- RelayPacket 测试(链上 VLESS UDP 依赖它)----------

type dgram struct {
	data []byte
	dst  addr.Socksaddr
}

// mockPC 是内存 link.PacketConn:ReadPacket 从 readQ 取,WritePacket 推 wrote;Close 解阻塞。
type mockPC struct {
	readQ chan dgram
	wrote chan dgram
	done  chan struct{}
	once  sync.Once
}

func newMockPC() *mockPC {
	return &mockPC{readQ: make(chan dgram, 8), wrote: make(chan dgram, 8), done: make(chan struct{})}
}
func (m *mockPC) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	select {
	case pk := <-m.readQ:
		_, _ = b.Write(pk.data)
		return pk.dst, nil
	case <-m.done:
		return addr.Socksaddr{}, io.EOF
	}
}
func (m *mockPC) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	select {
	case m.wrote <- dgram{data: append([]byte(nil), b.Bytes()...), dst: dst}:
		return nil
	case <-m.done:
		return io.ErrClosedPipe
	}
}
func (m *mockPC) Close() error                { m.once.Do(func() { close(m.done) }); return nil }
func (m *mockPC) LocalAddr() net.Addr         { return nil }
func (m *mockPC) SetDeadline(time.Time) error { return nil }
func (m *mockPC) Unwrap() any                 { return nil }

// TestRelayPacketForwardsDatagram:a 侧读到的包被原样(含逻辑目标)写到 b 侧。
func TestRelayPacketForwardsDatagram(t *testing.T) {
	a, b := newMockPC(), newMockPC()
	go func() { _ = RelayPacket(a, b) }()
	want := dgram{data: []byte("hello-udp"), dst: addr.FromFqdn("target.example", 53)}
	a.readQ <- want
	select {
	case got := <-b.wrote:
		if string(got.data) != "hello-udp" || got.dst.String() != "target.example:53" {
			t.Fatalf("转发的包不对:%q → %s", got.data, got.dst.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RelayPacket 未把 a 的包转到 b")
	}
	a.Close()
	b.Close()
}

// TestRelayPacketCloseNoHang:一端关闭后 RelayPacket 收尾返回,不泄漏 goroutine。
func TestRelayPacketCloseNoHang(t *testing.T) {
	a, b := newMockPC(), newMockPC()
	done := make(chan error, 1)
	go func() { done <- RelayPacket(a, b) }()
	a.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("一端关闭后 RelayPacket 未返回(泄漏)")
	}
}
