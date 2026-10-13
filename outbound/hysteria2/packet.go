package hysteria2

import (
	"net"
	"time"

	sbuf "github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/canceler"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

// packetConn 桥 hy2 库的 UDP 会话(QUIC datagram 上的 sessionID 会话,每包自带目标,可多目标;
// 超 MTU 由库分片/重组)↔ NTR link.PacketConn。客户端出站与服务端入站共用。
type packetConn struct {
	pc     N.PacketConn
	remote net.Addr // 服务端侧 = 客户端 QUIC 源地址(供运行时按来源 IP 计 max-ips);出站侧为 nil
}

var _ link.PacketConn = (*packetConn)(nil)

func (c *packetConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	for {
		sb := sbuf.NewPacket()
		dst, err := c.pc.ReadPacket(sb)
		if err != nil {
			sb.Release()
			return addr.Socksaddr{}, err
		}
		data := sb.Bytes()
		b.Reset()
		if len(data) > b.Tailroom() { // 超出 NTR 缓冲的包丢弃(保包边界),读下一个
			sb.Release()
			continue
		}
		copy(b.ExtendTail(len(data)), data)
		sb.Release()
		return toNTR(dst), nil
	}
}

func (c *packetConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	sb := sbuf.NewSize(b.Len())
	if _, err := sb.Write(b.Bytes()); err != nil {
		sb.Release()
		return err
	}
	return c.pc.WritePacket(sb, toSing(dst)) // 库侧负责 Release sb
}

func (c *packetConn) Close() error                  { return c.pc.Close() }
func (c *packetConn) LocalAddr() net.Addr           { return c.pc.LocalAddr() }
func (c *packetConn) SetDeadline(t time.Time) error { return c.pc.SetReadDeadline(t) }
func (c *packetConn) Unwrap() any                   { return nil }

// RemoteAddr 报客户端来源(服务端侧);运行时的准入据此取来源 IP。
func (c *packetConn) RemoteAddr() net.Addr { return c.remote }

// unwrapTimeout 剥掉服务端回调给的 canceler.TimeoutPacketConn(库的空闲超时包装):它的 active 时间戳在
// 读、写两侧无锁写入,运行时 udpNAT 读写并发即数据竞争(-race 实测)。空闲拆除由 udpNAT 每读前 arm 的
// deadline 承担(超时 → 关会话 → 库 onDestroy 摘表),故直接用库的 UDP 会话。
func unwrapTimeout(conn N.PacketConn) N.PacketConn {
	if t, ok := conn.(*canceler.TimeoutPacketConn); ok {
		if up, ok := t.Upstream().(N.PacketConn); ok {
			return up
		}
	}
	return conn
}

// sourceAddr 把库给的来源元数据转成 net.Addr(无效时 nil)。
func sourceAddr(src M.Socksaddr) net.Addr {
	if !src.IsValid() {
		return nil
	}
	return src.UDPAddr()
}
