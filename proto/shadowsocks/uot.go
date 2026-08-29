package shadowsocks

import (
	"context"
	"net"
	"time"

	singbuf "github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/uot"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// uotProxy 是 SS 的 UDP-over-TCP(UoT)变体:出站 UDP 不走原生 datagram,而是另拨一条 SS 流到 uot
// 魔术地址(sp.v2.udp-over-tcp.arpa),在流内以 uot 分帧承载多目标 UDP —— 与 sing-box/mihomo 的
// `udp_over_tcp` 互通(UDP 被封网络下可用)。禁改线格式(uot 分帧走 metacubex/sing common/uot)。
//
// 能力:委托 inner 的 TCP 握手(Client/Server)与原生 UDP 入站(PacketServer);仅把出站 UDP 从
// NativePacketConnClient(原生)换成 PacketConnClient(over-stream)—— 故 upstream.DialPacket 探测不到
// NativePacketConnClient,自动走 over-stream 的 UoT 路径。
type uotProxy struct {
	inner *Proxy
}

var (
	_ proxy.Client           = (*uotProxy)(nil)
	_ proxy.Server           = (*uotProxy)(nil)
	_ proxy.PacketConnClient = (*uotProxy)(nil)
	_ proxy.PacketServer     = (*uotProxy)(nil)
)

func (u *uotProxy) ClientHandshake(ctx context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.Stream, error) {
	return u.inner.ClientHandshake(ctx, below, key, dst)
}
func (u *uotProxy) ServerHandshake(ctx context.Context, below link.Stream, auth proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	return u.inner.ServerHandshake(ctx, below, auth)
}
func (u *uotProxy) ServePacket(ctx context.Context, pc net.PacketConn, sink func(link.PacketConn)) error {
	return u.inner.ServePacket(ctx, pc, sink)
}
func (u *uotProxy) ServerPacketConn(below link.Stream, dst addr.Socksaddr) (link.PacketConn, error) {
	return u.inner.ServerPacketConn(below, dst)
}

// isUoTMagic 判定 SS 目标是否为 uot 魔术地址(v2 / legacy)—— 是则该 SS 流承载 UoT 分帧。
func isUoTMagic(dst addr.Socksaddr) bool {
	return dst.Fqdn == uot.MagicAddress || dst.Fqdn == uot.LegacyMagicAddress
}

// ServerPacketConn 实现 proxy.PacketConnServer:当 ServerHandshake 判 SS 流为 UoT(魔术地址→Network=UDP)
// 时,核心调此。按魔术地址区分版本:v2(sp.v2.…)先读 uot request 头再分帧;v1(legacy,sp.…,mihomo
// 默认)无 request 头,直接分帧。桥成多目标 link.PacketConn。base Proxy 实现即可(自动检测,不需开关);
// uotProxy 委托至此。
func (p *Proxy) ServerPacketConn(below link.Stream, dst addr.Socksaddr) (link.PacketConn, error) {
	if dst.Fqdn == uot.LegacyMagicAddress {
		return &uotPacketConn{uc: uot.NewConn(below, uot.Request{}), stream: below}, nil
	}
	request, err := uot.ReadRequest(below)
	if err != nil {
		return nil, err
	}
	return &uotPacketConn{uc: uot.NewConn(below, *request), stream: below}, nil
}

var _ proxy.PacketConnServer = (*Proxy)(nil)

// DialPacketConn 实现 proxy.PacketConnClient:在 below 上跑 SS 握手到 uot 魔术地址,套 uot 客户端分帧
// (IsConnect=false=多目标 associate),桥成多目标 link.PacketConn。
func (u *uotProxy) DialPacketConn(ctx context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.PacketConn, error) {
	stream, err := u.inner.ClientHandshake(ctx, below, key, toNTR(uot.RequestDestination(uot.Version)))
	if err != nil {
		return nil, err
	}
	uc := uot.NewLazyConn(stream, uot.Request{IsConnect: false, Destination: toSing(dst)})
	return &uotPacketConn{uc: uc, stream: stream}, nil
}

// uotPacketConn 把 uot.Conn(sing 多目标 PacketConn)桥成 NTR link.PacketConn。
type uotPacketConn struct {
	uc     *uot.Conn
	stream link.Stream
}

var _ link.PacketConn = (*uotPacketConn)(nil)

func (c *uotPacketConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	for {
		sb := singbuf.NewSize(64 * 1024)
		dest, err := c.uc.ReadPacket(sb)
		if err != nil {
			sb.Release()
			return addr.Socksaddr{}, err
		}
		data := sb.Bytes()
		b.Reset()
		if len(data) > b.Tailroom() {
			sb.Release()
			continue // 巨型报超 buf 容量 → 丢弃继续,不破坏边界
		}
		copy(b.ExtendTail(len(data)), data)
		sb.Release()
		return toNTR(dest), nil
	}
}

func (c *uotPacketConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	sb := singbuf.NewSize(len(b.Bytes()))
	if _, err := sb.Write(b.Bytes()); err != nil {
		sb.Release()
		return err
	}
	// uot.WritePacket 自建 header 缓冲(无需输入 headroom),内部消费 sb。
	return c.uc.WritePacket(sb, toSing(dst))
}

func (c *uotPacketConn) Close() error                  { return c.stream.Close() }
func (c *uotPacketConn) LocalAddr() net.Addr           { return c.stream.LocalAddr() }
func (c *uotPacketConn) SetDeadline(t time.Time) error { return c.stream.SetDeadline(t) }
func (c *uotPacketConn) Unwrap() any                   { return c.stream }
