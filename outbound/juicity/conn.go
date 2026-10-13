package juicity

import (
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

// setCongestion 设拥塞控制。规范要求至少支持 BBR,故默认 BBR;"cubic" 用 quic-go 自带。
func setCongestion(conn *quic.Conn, name string) {
	switch name {
	case "cubic":
		return
	default: // "" / "bbr"
		conn.SetCongestionControl(congestion_meta2.NewBbrSender(
			congestion_meta2.DefaultClock{TimeFunc: time.Now},
			conn.InitialPacketSize(),
			congestion.ByteCount(congestion_meta1.InitialCongestionWindow),
		))
	}
}

// streamConn 把 QUIC 双向流抬成 link.Stream。QUIC 流的 Close 只关写方向(发 FIN),故
// CloseWrite = 流 Close(供 relay 半关);Close 另取消读方向,做全关。
type streamConn struct {
	st      *quic.Stream
	local   net.Addr
	remote  net.Addr
	once    sync.Once
	onClose func() // 客户端:归还会话的活跃流计数
}

var _ link.Stream = (*streamConn)(nil)

func newStreamConn(st *quic.Stream, conn *quic.Conn, onClose func()) *streamConn {
	return &streamConn{st: st, local: conn.LocalAddr(), remote: conn.RemoteAddr(), onClose: onClose}
}

func (c *streamConn) Read(b []byte) (int, error)  { return c.st.Read(b) }
func (c *streamConn) Write(b []byte) (int, error) { return c.st.Write(b) }
func (c *streamConn) CloseWrite() error           { return c.st.Close() }

func (c *streamConn) Close() error {
	c.st.CancelRead(0)
	err := c.st.Close()
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func (c *streamConn) LocalAddr() net.Addr                { return c.local }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }
func (c *streamConn) Unwrap() any                        { return c.st }

// packetConn 在一条承载流(可能已被计量包裹)上收发 UDP 帧 [socks 地址][len][负载]。两端同一套语义:
// ReadPacket 返回帧里的地址(客户端=来源,服务端=目标),WritePacket 把给定地址编进帧
// (客户端=目标,服务端=来源)。写整帧一次 Write + 互斥,多 goroutine 并发写不交错。
type packetConn struct {
	s   link.Stream
	wmu sync.Mutex
}

var _ link.PacketConn = (*packetConn)(nil)

// RemoteAddr 报承载流的对端(服务端侧 = 客户端 QUIC 源地址;运行时准入据此取来源 IP)。
func (p *packetConn) RemoteAddr() net.Addr { return p.s.RemoteAddr() }

var framePool = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

func (p *packetConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	a, n, err := readUDPFrame(p.s, b.ExtendTail(b.Tailroom()))
	if err != nil {
		b.Truncate(0)
		return addr.Socksaddr{}, err
	}
	b.Truncate(n)
	return a, nil
}

func (p *packetConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	fp := framePool.Get().(*[]byte)
	defer framePool.Put(fp)
	frame, err := appendUDPFrame((*fp)[:0], dst, b.Bytes())
	if err != nil {
		return err
	}
	*fp = frame
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_, err = p.s.Write(frame)
	return err
}

func (p *packetConn) Close() error                  { return p.s.Close() }
func (p *packetConn) LocalAddr() net.Addr           { return p.s.LocalAddr() }
func (p *packetConn) SetDeadline(t time.Time) error { return p.s.SetDeadline(t) }
func (p *packetConn) Unwrap() any                   { return p.s }
