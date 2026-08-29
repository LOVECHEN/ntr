// Package anytls 把 AnyTLS 接入 NTR:客户端出站 + 会话解复用入站。
//
// ★用第三方权威实现 github.com/anytls/sing-anytls(与 mihomo/sing-box 互通)。AnyTLS 是
// 会话式协议:一条 TLS 连接上多路复用多个代理流 + padding 抗分析,故不套 NTR 的流式栈契约,
// 而是走 endpoint.Outbound(客户端 CreateProxy 开流)+ 会话解复用 InboundHandler(服务端)。
package anytls

import (
	"context"
	cryptotls "crypto/tls"
	"net"
	"net/netip"
	"os"
	"time"

	sanytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = (*Outbound)(nil)

// Options 是 AnyTLS 出站配置。
type Options struct {
	Server   string // 上游 host:port
	Password string
	SNI      string
	Insecure bool
	ALPN     []string
}

// Outbound 是 AnyTLS 出站:内部维护到上游的 TLS+会话客户端,DialStream 开一条复用流。
// UDP 走 UoT(UDP-over-TCP,与 sing-box/mihomo 一致):uotClient 在会话上开一条到 uot 魔术地址的
// 复用流、以 uot 帧承载 UDP 包(禁改协议线格式:anytls 只多开一条普通复用流,UDP 语义全在 uot 层)。
type Outbound struct {
	client    *sanytls.Client
	uotClient *uot.Client
}

// NewOutbound 构造 AnyTLS 出站。
func NewOutbound(o Options) (*Outbound, error) {
	tlsConfig := &cryptotls.Config{
		ServerName:         o.SNI,
		InsecureSkipVerify: o.Insecure,
		NextProtos:         o.ALPN,
		MinVersion:         cryptotls.VersionTLS12,
	}
	dialer := &net.Dialer{}
	dialOut := func(ctx context.Context) (net.Conn, error) {
		raw, err := dialer.DialContext(ctx, "tcp", o.Server)
		if err != nil {
			return nil, err
		}
		tc := cryptotls.Client(raw, tlsConfig)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return tc, nil
	}
	client, err := sanytls.NewClient(context.Background(), sanytls.ClientConfig{
		Password:                 o.Password,
		DialOut:                  dialOut,
		Logger:                   logger.NOP(),
		IdleSessionCheckInterval: 30 * time.Second,
		IdleSessionTimeout:       30 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	ob := &Outbound{client: client}
	// UoT 客户端:拨号器就是「在 anytls 会话上开一条到给定目标的复用流」(client.CreateProxy);
	// uot.Client 会拨到 uot 魔术地址、以 uot 帧在这条流上收发 UDP 包(与 sing-box anytls 出站同款)。
	ob.uotClient = &uot.Client{Dialer: anytlsDialer(client.CreateProxy), Version: uot.Version}
	return ob, nil
}

// DialStream 在 AnyTLS 会话上开一条到 dst 的复用流。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	conn, err := o.client.CreateProxy(ctx, toSing(dst))
	if err != nil {
		return nil, err
	}
	return connStream{conn}, nil
}

// DialPacket:AnyTLS UDP —— 经 UoT 在 anytls 会话上开一条 uot 流承载(多目标:每包自带 dst)。
func (o *Outbound) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	pc, err := o.uotClient.ListenPacket(ctx, toSing(dst))
	if err != nil {
		return nil, err
	}
	return &udpPacketConn{pc: pc}, nil
}

// anytlsDialer 把 client.CreateProxy(在会话上开一条到目标的复用流)适配成 uot.Client 需要的 N.Dialer。
// uot 只用 DialContext(TCP 语义)拨到魔术地址;ListenPacket 不会被 uot.Client 调到,给个占位。
type anytlsDialer func(ctx context.Context, destination M.Socksaddr) (net.Conn, error)

func (d anytlsDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	return d(ctx, destination)
}
func (anytlsDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// udpPacketConn 把 uot 的 net.PacketConn(ReadFrom/WriteTo 带 net.Addr,uot 帧已代管寻址)
// 适配成 NTR link.PacketConn(buf.Buffer + Socksaddr);多目标由每次 WritePacket 的 dst 独立寻址。
type udpPacketConn struct{ pc net.PacketConn }

var _ link.PacketConn = (*udpPacketConn)(nil)

func (c *udpPacketConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	b.Reset()
	n, netAddr, err := c.pc.ReadFrom(b.ExtendTail(b.Tailroom()))
	if err != nil {
		return addr.Socksaddr{}, err
	}
	b.Truncate(n)
	return netAddrToNTR(netAddr), nil
}

func (c *udpPacketConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	_, err := c.pc.WriteTo(b.Bytes(), toSing(dst))
	return err
}

func (c *udpPacketConn) Close() error                  { return c.pc.Close() }
func (c *udpPacketConn) LocalAddr() net.Addr           { return c.pc.LocalAddr() }
func (c *udpPacketConn) SetDeadline(t time.Time) error { return c.pc.SetDeadline(t) }
func (c *udpPacketConn) Unwrap() any                   { return nil }

func toSing(a addr.Socksaddr) M.Socksaddr {
	return M.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}
func toNTR(a M.Socksaddr) addr.Socksaddr {
	return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}

// netAddrToNTR 把 uot 回读的 net.Addr(sing M.Socksaddr 或 *net.UDPAddr)转 NTR Socksaddr。
func netAddrToNTR(a net.Addr) addr.Socksaddr {
	if sa, ok := a.(M.Socksaddr); ok {
		return toNTR(sa)
	}
	if ua, ok := a.(*net.UDPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ua.IP); ok {
			return addr.FromIPPort(netip.AddrPortFrom(ip.Unmap(), uint16(ua.Port)))
		}
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return addr.FromIPPort(ap)
	}
	return addr.Socksaddr{}
}

// connStream 把 sing 的 net.Conn 抬成 link.Stream。
type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }
