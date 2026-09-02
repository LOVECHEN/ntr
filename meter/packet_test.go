package meter

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

// fakePC 是内存 datagram 端:ReadPacket 吐固定长度包,WritePacket 记录长度。
type fakePC struct {
	readLen int
	wrote   []int
}

func (f *fakePC) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	b.Reset()
	copy(b.ExtendTail(f.readLen), make([]byte, f.readLen))
	return addr.Socksaddr{}, nil
}
func (f *fakePC) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error {
	f.wrote = append(f.wrote, b.Len())
	return nil
}
func (f *fakePC) Close() error                { return nil }
func (f *fakePC) LocalAddr() net.Addr         { return nil }
func (f *fakePC) SetDeadline(time.Time) error { return nil }
func (f *fakePC) Unwrap() any                 { return nil }

var _ link.PacketConn = (*fakePC)(nil)

// TestWrapPacketCounts:UDP-over-stream 的 datagram 级计量 —— ReadPacket 按 payload 计上行、
// WritePacket 计下行,落到该用户的 Cell(与流侧 Wrap 同口径)。
func TestWrapPacketCounts(t *testing.T) {
	reg := NewRegistry()
	id := reg.IDForBill("alice@in")
	m, done, ok := reg.Open(id, netip.MustParseAddr("10.0.0.1"), func() {})
	if !ok {
		t.Fatal("Open 应放行")
	}
	defer done()
	inner := &fakePC{readLen: 700}
	pc := WrapPacket(inner, m)
	b := buf.New()
	for range 3 {
		if _, err := pc.ReadPacket(b); err != nil {
			t.Fatal(err)
		}
	}
	w := buf.New()
	w.ExtendTail(150)
	if err := pc.WritePacket(w, addr.Socksaddr{}); err != nil {
		t.Fatal(err)
	}
	m.Flush()
	var st *UserStat
	for _, s := range reg.Snapshot() {
		if s.Bill == "alice@in" {
			st = &s
			break
		}
	}
	if st == nil || st.Up != 2100 || st.Down != 150 {
		t.Fatalf("alice@in 上行/下行应为 2100/150,实为 %+v", st)
	}
	if pc.Unwrap() != link.PacketConn(inner) {
		t.Fatal("Unwrap 应返回被包裹的下层")
	}
}
