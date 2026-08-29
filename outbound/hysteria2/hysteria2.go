// Package hysteria2 把 Hysteria2 接入 NTR:QUIC 之上的客户端出站 + 服务端入站。
//
// ★用第三方权威实现 github.com/metacubex/sing-quic/hysteria2(与 mihomo/sing-box 互通)。
// hy2 跑在 QUIC(UDP)上,是会话式协议:客户端 DialConn 在 QUIC 连接上开流,服务端在 UDP
// socket 上 Service.Start 接受 QUIC 连接 + 鉴权 + 解复用。故走 endpoint.Outbound + 自管 UDP
// 的入站 Runner,不套 NTR 的流式栈契约。
package hysteria2

import (
	"context"
	"errors"
	"net"
	"net/netip"

	quic "github.com/metacubex/quic-go"
	qtls "github.com/metacubex/sing-quic"
	"github.com/metacubex/sing-quic/hysteria2"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	mtls "github.com/metacubex/tls"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = (*Outbound)(nil)

var errUDPNotReady = errors.New("hysteria2: UDP over QUIC datagram not implemented yet")

// Options 是 Hysteria2 出站配置。
type Options struct {
	Server   string // 上游 host:port
	Password string
	SNI      string
	Insecure bool
	Obfs     string // salamander obfs 口令(可空;与 sing-box/mihomo hy2 obfs=salamander 互通)
	UpMbps   uint64 // 可选带宽(BBR/Brutal);0 = 用默认拥塞控制
	DownMbps uint64
}

// Outbound 是 Hysteria2 出站:内部持一个 QUIC 客户端,DialStream 在其上开代理流。
type Outbound struct {
	client *hysteria2.Client
}

// NewOutbound 构造 Hysteria2 出站。
func NewOutbound(o Options) (*Outbound, error) {
	tlsConfig := &mtls.Config{
		ServerName:         o.SNI,
		InsecureSkipVerify: o.Insecure,
		NextProtos:         []string{"h3"},
	}
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:       context.Background(),
		Logger:        logger.NOP(),
		ServerAddress:      M.ParseSocksaddr(o.Server),
		Password:           o.Password,
		SalamanderPassword: o.Obfs,
		TLSConfig:          tlsConfig,
		SendBPS:       o.UpMbps * 1000 * 1000 / 8,
		ReceiveBPS:    o.DownMbps * 1000 * 1000 / 8,
		UdpMTU:        1200,
		PacketListener: qtls.PacketDialerFunc(func(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
			return net.ListenUDP("udp", nil) // 临时本地 UDP socket
		}),
		QuicDialer: qtls.QuicDialerFunc(dialQUIC),
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{client: client}, nil
}

// dialQUIC:在 listener 给的本地 UDP socket 上向 addr 拨一条 QUIC 连接。
func dialQUIC(ctx context.Context, addr string, listener qtls.PacketDialer, tlsCfg *mtls.Config, cfg *quic.Config, early bool) (net.PacketConn, *quic.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, err
	}
	pc, err := listener.ListenPacket(ctx, "udp", ":0", udpAddr.AddrPort())
	if err != nil {
		return nil, nil, err
	}
	var conn *quic.Conn
	if early {
		conn, err = quic.DialEarly(ctx, pc, udpAddr, tlsCfg, cfg)
	} else {
		conn, err = quic.Dial(ctx, pc, udpAddr, tlsCfg, cfg)
	}
	if err != nil {
		_ = pc.Close()
		return nil, nil, err
	}
	return pc, conn, nil
}

// DialStream 在 hy2 QUIC 连接上开一条到 dst 的代理流。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	conn, err := o.client.DialConn(ctx, toSing(dst))
	if err != nil {
		return nil, err
	}
	return connStream{conn}, nil
}

// DialPacket:hy2 UDP over QUIC datagram 待接入。
func (o *Outbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, errUDPNotReady
}

func toSing(a addr.Socksaddr) M.Socksaddr {
	return M.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}
func toNTR(a M.Socksaddr) addr.Socksaddr {
	return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}

type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

// NeedHandshake 转发底层 hy2 clientConn 的懒发送状态:其目标 header 首次 Write 才 flush。
// 反连 Bridge 据此在跑 muxcool ServerWorker(先读不写)前主动 flush,避免与 Portal 互等死锁。
func (c connStream) NeedHandshake() bool {
	if h, ok := c.Conn.(interface{ NeedHandshake() bool }); ok {
		return h.NeedHandshake()
	}
	return false
}
