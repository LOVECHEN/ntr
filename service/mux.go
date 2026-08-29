package service

import (
	"context"
	"net"
	"time"

	singmux "github.com/metacubex/sing-mux"
	singbuf "github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
)

// mux 服务端解复用:任何入站握手若解出目标 == sing-mux 魔术域名(sp.mux.sing-box.arpa),该流即
// 一条 mux 承载连接。此处用 sing-mux Service 解出其上的多条子流,每条按自带真实目标经统一 relay/
// udpNAT 落地到出站 —— 与 sing-box / mihomo 的 mux 服务端线级互通。放 service(而非 outbound/mux)
// 是为复用已有 relay+udpNAT 且避免 service↔outbound/mux 循环;sing-mux 是第三方库,不违协议门禁。

// isMuxCarrier 报告握手目标是否为 mux 承载魔术目标。
func isMuxCarrier(dst addr.Socksaddr) bool {
	return dst.Fqdn != "" && dst.Fqdn == singmux.Destination.Fqdn
}

// handleMuxCarrier 把一条 mux 承载 stream 交 sing-mux Service 解复用,阻塞至承载关闭。
func handleMuxCarrier(ctx context.Context, carrier link.Stream, resolver OutboundResolver) error {
	svc, err := singmux.NewService(singmux.ServiceOptions{
		NewStreamContext: func(c context.Context, _ net.Conn) context.Context { return c },
		Logger:           logger.NOP(),
		Handler:          muxHandler{resolver: resolver},
	})
	if err != nil {
		return err
	}
	return svc.NewConnection(ctx, carrier, M.Metadata{})
}

// muxHandler 实现 sing-mux ServiceHandler:每条子流按自带真实目标落地。
type muxHandler struct{ resolver OutboundResolver }

// NewConnection:一条 TCP 子流(md.Destination 已是真实目标)→ 解析出站 → 拨 → relay。
func (h muxHandler) NewConnection(ctx context.Context, conn net.Conn, md M.Metadata) error {
	dst := toNTRAddr(md.Destination)
	out, err := h.resolver.Resolve(ctx, dst)
	if err != nil {
		return err
	}
	up, err := out.DialStream(ctx, dst)
	if err != nil {
		return err
	}
	return relay.Relay(connStream{conn}, up)
}

// NewPacketConnection:一条 UDP 子流(可能多目标,每包自带地址)→ 桥成 link.PacketConn → udpNAT。
func (h muxHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, md M.Metadata) error {
	client := &muxPacketConn{
		pc:    conn,
		dst:   toNTRAddr(md.Destination),
		front: N.CalculateFrontHeadroom(conn),
		rear:  N.CalculateRearHeadroom(conn),
	}
	defer client.Close()
	return udpNAT(ctx, client, h.resolver)
}

func (h muxHandler) NewError(context.Context, error) {}

// muxPacketConn 桥 sing-mux UDP 子流(sing PacketConn)↔ NTR link.PacketConn(多目标,每包自带 dst)。
type muxPacketConn struct {
	pc    N.PacketConn
	dst   addr.Socksaddr
	front int
	rear  int
}

var _ link.PacketConn = (*muxPacketConn)(nil)

func (c *muxPacketConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	for {
		sb := singbuf.NewSize(64 * 1024)
		src, err := c.pc.ReadPacket(sb)
		if err != nil {
			sb.Release()
			return addr.Socksaddr{}, err
		}
		data := sb.Bytes()
		b.Reset()
		if len(data) > b.Tailroom() {
			sb.Release()
			continue
		}
		copy(b.ExtendTail(len(data)), data)
		sb.Release()
		if src.Fqdn == "" && !src.Addr.IsValid() {
			return c.dst, nil // 子流单目标时对端可能不带地址,回落握手目标
		}
		return toNTRAddr(src), nil
	}
}

func (c *muxPacketConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	payload := b.Bytes()
	sb := singbuf.NewSize(c.front + len(payload) + c.rear)
	sb.Resize(c.front, 0)
	if _, err := sb.Write(payload); err != nil {
		sb.Release()
		return err
	}
	return c.pc.WritePacket(sb, M.Socksaddr{Addr: dst.Addr, Port: dst.Port, Fqdn: dst.Fqdn})
}

func (c *muxPacketConn) Close() error                  { return c.pc.Close() }
func (c *muxPacketConn) LocalAddr() net.Addr           { return c.pc.LocalAddr() }
func (c *muxPacketConn) SetDeadline(t time.Time) error { return c.pc.SetReadDeadline(t) }
func (c *muxPacketConn) Unwrap() any                   { return nil }

func toNTRAddr(a M.Socksaddr) addr.Socksaddr {
	return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}
