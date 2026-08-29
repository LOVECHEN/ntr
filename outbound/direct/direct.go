// Package direct 是"直连"出站:把 dst 交给系统栈拨号,不经任何上游代理。
//
// 承 §2.3:Outbound 以本机身份出示凭据向上游认证、不进凭据树 —— direct 没有上游,
// 就是终点。它对协议无感知,只吐 link.Stream/PacketConn 给 relay。
package direct

import (
	"context"
	"fmt"
	"net"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = Outbound{}

// Outbound 是直连出站。零值可用;Dialer 可注入超时/本地地址/Control 等策略。
type Outbound struct {
	Dialer net.Dialer
}

// DialStream 拨 TCP 到 dst(域名交系统解析器)。
func (o Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	conn, err := o.Dialer.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, err
	}
	return connStream{Conn: conn}, nil
}

// DialPacket 拨 UDP 到 dst,返回单目标 PacketConn(连接式 UDP:内核只收发该对端)。
// 多目标(SOCKS UDP ASSOCIATE / TUN)由上游 udpnat 拆成多条单目标 assoc,不在此。
func (o Outbound) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	conn, err := o.Dialer.DialContext(ctx, "udp", dst.String())
	if err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("direct: 期望 *net.UDPConn,得到 %T", conn)
	}
	return &udpConn{UDPConn: uc, dst: dst}, nil
}

// udpConn 把连接式 *net.UDPConn 抬成 link.PacketConn(单目标,dst=连接对端)。
type udpConn struct {
	*net.UDPConn
	dst addr.Socksaddr
}

var _ link.PacketConn = (*udpConn)(nil)

// ReadPacket 收一个 datagram 到 b 的载荷区(dst 恒为连接对端)。
func (c *udpConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	n, err := c.Read(b.ExtendTail(b.Tailroom()))
	if err != nil {
		return addr.Socksaddr{}, err
	}
	b.Truncate(n) // 收缩到实收字节
	return c.dst, nil
}

// WritePacket 把 b 作为一个 datagram 发给连接对端。
func (c *udpConn) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error {
	_, err := c.Write(b.Bytes())
	return err
}

// Close/LocalAddr/SetDeadline 由内嵌 *net.UDPConn 提供。
func (c *udpConn) Unwrap() any { return c.UDPConn }

// connStream 把 *net.TCPConn 抬成 link.Stream。它是链底,Unwrap 返回底层 net.Conn
// 供能力发现(如需 splice/ReadFrom 时向下探到裸 *net.TCPConn)。
type connStream struct{ net.Conn }

func (c connStream) Unwrap() any { return c.Conn }
