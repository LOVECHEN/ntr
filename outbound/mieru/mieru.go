// Package mieru 把 mieru(enfein/mieru)接入 NTR 出站。
//
// ★用官方权威库 github.com/enfein/mieru/v3(mihomo 亦用此库),禁改线格式。mieru 是会话式协议:
// 客户端库自管到服务端的连接(TCP 或 UDP 传输 + 自有分段/加密/多路复用),不套 NTR 的流式栈,
// 故走 endpoint.Outbound(DialStream 直接问 mieru 客户端要一条到目标的 net.Conn)。
//
// 仅出站(客户端):mihomo 是三家中唯一有 mieru 的(client+listener),故对 mihomo mieru 入站
// 交叉验证 NTR 客户端(禁改线格式的活体证明);NTR 侧 mieru 服务端后续增量再接(需注入 NTR 监听工厂)。
package mieru

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	mieruclient "github.com/enfein/mieru/v3/apis/client"
	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = (*Outbound)(nil)

// Options 是 mieru 出站配置。Server=host:port;Transport=mieru 传输(TCP/UDP,默认 TCP);
// Username/Password=用户凭据;Multiplexing 可选(MULTIPLEXING_OFF/LOW/MIDDLE/HIGH)。
type Options struct {
	Server       string
	Transport    string
	Username     string
	Password     string
	Multiplexing string
}

// Outbound 是 mieru 出站:惰性 Start 客户端,DialStream 向其要一条到目标的连接。
type Outbound struct {
	client  mieruclient.Client
	mu      sync.Mutex
	started bool
}

// NewOutbound 构造 mieru 出站(按 mihomo buildMieruClientConfig 的 protobuf 装配,字节对齐)。
func NewOutbound(o Options) (*Outbound, error) {
	if o.Server == "" {
		return nil, errors.New("mieru: server 为空")
	}
	if o.Username == "" || o.Password == "" {
		return nil, errors.New("mieru: 需 username + password")
	}
	host, portStr, err := net.SplitHostPort(o.Server)
	if err != nil {
		return nil, fmt.Errorf("mieru: server 需 host:port:%w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("mieru: port:%w", err)
	}

	tp := mierupb.TransportProtocol_TCP.Enum()
	if o.Transport == "UDP" {
		tp = mierupb.TransportProtocol_UDP.Enum()
	}

	ep := &mierupb.ServerEndpoint{
		PortBindings: []*mierupb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: tp}},
	}
	if net.ParseIP(host) != nil {
		ep.IpAddress = proto.String(host)
	} else {
		ep.DomainName = proto.String(host)
	}

	profile := &mierupb.ClientProfile{
		ProfileName: proto.String("ntr-mieru"),
		User:        &mierupb.User{Name: proto.String(o.Username), Password: proto.String(o.Password)},
		Servers:     []*mierupb.ServerEndpoint{ep},
	}
	if lvl, ok := mierupb.MultiplexingLevel_value[o.Multiplexing]; ok {
		profile.Multiplexing = &mierupb.MultiplexingConfig{Level: mierupb.MultiplexingLevel(lvl).Enum()}
	}

	c := mieruclient.NewClient()
	// ★必须注入 Dialer/PacketDialer:profile 无内嵌 dialer 且二者皆 nil 时 mieru 的 mux 不设 dialer,
	// DialContext 会挂死(见 appctlcommon.NewClientMuxFromProfile)。TCP 用标准 net.Dialer,
	// UDP 传输用 udpDialer(ListenPacket)。
	// ★Resolver 必须给:服务端端点为域名时,mieru 用它先解析出 IP 再拨号;缺省(NilDNSResolver)
	// 会「disable DNS resolution」→ 域名服务端连不上。标准库 *net.Resolver 直接满足接口。
	if err := c.Store(&mieruclient.ClientConfig{
		Profile:      profile,
		Dialer:       &net.Dialer{},
		PacketDialer: udpDialer{},
		Resolver:     net.DefaultResolver,
	}); err != nil {
		return nil, fmt.Errorf("mieru: 存配置:%w", err)
	}
	return &Outbound{client: c}, nil
}

// udpDialer 为 mieru UDP 传输提供 PacketDialer(监听随机本地端口,mieru 自己 WriteTo 服务端)。
type udpDialer struct{}

func (udpDialer) ListenPacket(ctx context.Context, network, laddr, _ string) (net.PacketConn, error) {
	if laddr == "" {
		laddr = ":0"
	}
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, laddr)
}

func (o *Outbound) ensureStarted() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.started {
		return nil
	}
	if err := o.client.Start(); err != nil {
		return fmt.Errorf("mieru: start:%w", err)
	}
	o.started = true
	return nil
}

// DialStream 向 mieru 客户端要一条到 dst 的 TCP 代理连接。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	if err := o.ensureStarted(); err != nil {
		return nil, err
	}
	conn, err := o.client.DialContext(ctx, toMieruAddr(dst, "tcp"))
	if err != nil {
		return nil, fmt.Errorf("mieru: dial:%w", err)
	}
	return connStream{conn}, nil
}

// DialPacket 走 mieru 的 UDP-over-tunnel:向 mieru 客户端要一条 UDP-associate 流,套官方
// PacketOverStreamTunnel(分帧)+ UDPAssociateWrapper(socks5 UDP 寻址),适配成 NTR link.PacketConn。
// 多目标:每次 WritePacket 的 dst 独立寻址(与 mihomo mieru `udp: true` 一致)。
func (o *Outbound) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	if err := o.ensureStarted(); err != nil {
		return nil, err
	}
	c, err := o.client.DialContext(ctx, toMieruAddr(dst, "udp"))
	if err != nil {
		return nil, fmt.Errorf("mieru: dial udp:%w", err)
	}
	pc := mierucommon.NewUDPAssociateWrapper(mierucommon.NewPacketOverStreamTunnel(c))
	return &udpPacketConn{pc: pc, below: c}, nil
}

// udpPacketConn 把 mieru 的 net.PacketConn(UDPAssociateWrapper,ReadFrom/WriteTo 带 net.Addr,
// socks5 UDP 头已由它代管)适配成 NTR link.PacketConn(buf.Buffer + Socksaddr)。
type udpPacketConn struct {
	pc    net.PacketConn
	below net.Conn
}

var _ link.PacketConn = (*udpPacketConn)(nil)

func (c *udpPacketConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	b.Reset()
	n, netAddr, err := c.pc.ReadFrom(b.ExtendTail(b.Tailroom()))
	if err != nil {
		return addr.Socksaddr{}, err
	}
	b.Truncate(n)
	return netAddrToSocks(netAddr), nil
}

func (c *udpPacketConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	// UDPAssociateWrapper.WriteTo 用 NetAddrSpec.From 解 addr(值传保留 FQDN),再前置 socks5 UDP 头。
	_, err := c.pc.WriteTo(b.Bytes(), toMieruAddr(dst, "udp"))
	return err
}

func (c *udpPacketConn) Close() error                  { return c.pc.Close() }
func (c *udpPacketConn) LocalAddr() net.Addr           { return c.pc.LocalAddr() }
func (c *udpPacketConn) SetDeadline(t time.Time) error { return c.pc.SetDeadline(t) }
func (c *udpPacketConn) Unwrap() any                   { return c.below }

// netAddrToSocks 把 mieru 回读的 *net.UDPAddr(响应恒为 IP)转 NTR Socksaddr。
func netAddrToSocks(a net.Addr) addr.Socksaddr {
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

// Close 停止 mieru 客户端。
func (o *Outbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.started && o.client.IsRunning() {
		return o.client.Stop()
	}
	return nil
}

// toMieruAddr 把 NTR 目标转成 mieru 的 NetAddrSpec(net.Addr)。
func toMieruAddr(dst addr.Socksaddr, network string) mierumodel.NetAddrSpec {
	s := mierumodel.NetAddrSpec{Net: network}
	if dst.IsFqdn() {
		s.AddrSpec = mierumodel.AddrSpec{FQDN: dst.Fqdn, Port: int(dst.Port)}
	} else {
		s.AddrSpec = mierumodel.AddrSpec{IP: net.IP(dst.Addr.AsSlice()), Port: int(dst.Port)}
	}
	return s
}

type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

var _ link.Stream = connStream{}
