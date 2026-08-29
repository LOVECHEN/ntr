// Package mux 接入 sing 家族多路复用(h2mux/smux/yamux)——与 sing-box / mihomo 线级互通。
//
// ★桥 metacubex/sing-mux(非自写):mux 是 Session 概念,一条底层承载连接上跑多条逻辑子流。
// 布局:mux 出站【包一个 base 出站】—— sing-mux Client 的 dialer 用 base.DialStream 拨【魔术目标】
// sp.mux.sing-box.arpa 建承载连接(即一条完整的 base 协议流),再在其上复用子流;每子流写 sing-mux
// 流请求头(真实目标),故对 base 协议零改动、对 mux 线格式零改动。
//
// 服务端识别:任何入站握手若解出目标 == 魔术域名,即把该流交 server.go 的 mux 解复用(见 service)。
package mux

import (
	"context"
	"errors"
	"net"
	"time"

	singmux "github.com/metacubex/sing-mux"
	singbuf "github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var (
	errNotPacket               = errors.New("mux: UDP 子流未实现 PacketConn 能力")
	errListenPacketUnsupported = errors.New("mux: dialer.ListenPacket 不应被调用(UDP 子流跑在承载之上)")
)

var _ endpoint.Outbound = (*Outbound)(nil)

// Options 是 mux 出站配置。Protocol ∈ {h2mux(默认),smux,yamux};其余对齐 sing-box 语义。
type Options struct {
	Protocol       string
	MaxConnections int
	MinStreams     int
	MaxStreams     int
	Padding        bool
}

// IsCarrier 报告握手解出的目标是否为 mux 承载连接的魔术目标(服务端据此分派到解复用)。
func IsCarrier(dst addr.Socksaddr) bool {
	return dst.IsFqdn() && dst.Fqdn == singmux.Destination.Fqdn
}

// Outbound 是 mux 出站:包一个 base 出站,经 sing-mux Client 把每条 DialStream/DialPacket
// 复用到少数几条 base 承载连接上。
type Outbound struct {
	client *singmux.Client
	base   endpoint.Outbound
}

// NewOutbound 用 base 出站构造 mux 出站。base 负责把承载连接拨到魔术目标(即用它跑 vless/trojan…)。
//
// ★协议默认取 smux(而非 sing-mux 原生默认 h2mux):h2mux 客户端走 x/net/http2,而 Go 1.27 起
// x/net 默认转发到标准库 net/http,后者严格拒 sing-mux 构造的 nil Request.Header(见 PROGRESS)。
// smux/yamux 无此问题、任意构建可用;协议由客户端选、服务端跟随,故默认 smux 与三家全互通。
// 显式要 h2mux 客户端须以 `-tags http2legacy` 构建(build.sh 已带),让 x/net 用自带宽松 http2。
func NewOutbound(base endpoint.Outbound, o Options) (*Outbound, error) {
	protocol := o.Protocol
	if protocol == "" {
		protocol = "smux"
	}
	client, err := singmux.NewClient(singmux.Options{
		Dialer:         baseDialer{base},
		Protocol:       protocol,
		MaxConnections: o.MaxConnections,
		MinStreams:     o.MinStreams,
		MaxStreams:     o.MaxStreams,
		Padding:        o.Padding,
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{client: client, base: base}, nil
}

// DialStream 开一条 mux 子流承载 dst(TCP)。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	c, err := o.client.DialContext(ctx, N.NetworkTCP, toSing(dst))
	if err != nil {
		return nil, err
	}
	return connStream{c}, nil
}

// DialPacket 开一条 mux 子流承载 dst(UDP,单目标)。sing-mux 的 UDP 子流是帧对齐 PacketConn。
func (o *Outbound) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	c, err := o.client.DialContext(ctx, N.NetworkUDP, toSing(dst))
	if err != nil {
		return nil, err
	}
	pc, ok := c.(N.PacketConn)
	if !ok {
		_ = c.Close()
		return nil, errNotPacket
	}
	return &packetConn{
		pc:    pc,
		dst:   dst,
		front: N.CalculateFrontHeadroom(pc),
		rear:  N.CalculateRearHeadroom(pc),
	}, nil
}

// Close 关闭 mux 客户端(断所有承载连接)。
func (o *Outbound) Close() error { return o.client.Close() }

// baseDialer 把 endpoint.Outbound 抬成 sing 的 N.Dialer:DialContext 用 base.DialStream 拨承载连接。
// sing-mux 只用 TCP 拨承载(魔术目标),UDP 子流跑在承载之上,故 ListenPacket 不会被调用。
type baseDialer struct{ base endpoint.Outbound }

func (d baseDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	// link.Stream 内嵌 net.Conn,可直接作 net.Conn 返回。
	return d.base.DialStream(ctx, toNTR(destination))
}

func (d baseDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errListenPacketUnsupported
}

func toSing(a addr.Socksaddr) M.Socksaddr {
	return M.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}
func toNTR(a M.Socksaddr) addr.Socksaddr {
	return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}

// connStream 把 mux 子流(net.Conn)抬成 link.Stream。
type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

// packetConn 把 mux 的单目标 UDP 子流(sing PacketConn)桥成 NTR link.PacketConn(dst 恒握手目标)。
// buffer-bridge 同 ss/vmess:读进 sing 缓冲拷入 NTR b;写用带 headroom 的独立 sing 缓冲让 sing 就地
// 封帧,且不手放(sing WritePacket 内部 defer Release,共享 NTR 缓冲会双释放)。
type packetConn struct {
	pc    N.PacketConn
	dst   addr.Socksaddr
	front int
	rear  int
}

var _ link.PacketConn = (*packetConn)(nil)

func (c *packetConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	for {
		sb := singbuf.NewSize(64 * 1024)
		if _, err := c.pc.ReadPacket(sb); err != nil {
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
		return c.dst, nil
	}
}

func (c *packetConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	payload := b.Bytes()
	sb := singbuf.NewSize(c.front + len(payload) + c.rear)
	sb.Resize(c.front, 0)
	if _, err := sb.Write(payload); err != nil {
		sb.Release()
		return err
	}
	return c.pc.WritePacket(sb, toSing(dst))
}

func (c *packetConn) Close() error                  { return c.pc.Close() }
func (c *packetConn) LocalAddr() net.Addr           { return c.pc.LocalAddr() }
func (c *packetConn) SetDeadline(t time.Time) error { return c.pc.SetReadDeadline(t) }
func (c *packetConn) Unwrap() any                   { return nil }
