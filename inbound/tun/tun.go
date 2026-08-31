//go:build with_tun

// Package tun 是 TUN 入站:自管一张 TUN 网卡(L3 IP),把捕获的 IP 流量经 NTR 原生用户态栈
// (netstack,gVisor)合成成 L4 连接,每条 TCP 经 out.DialStream + relay 落地、每条 UDP 经
// out.DialPacket 落地。出站 out 由 config 选出且 protocol-agnostic —— 故【任何出站协议都能 TUN】。
// 自管设备,走 config 的 Instance{Listen,Run} 范式(同 hy2/tuic)。需 -tags with_tun 编入。
package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
	"github.com/LOVECHEN/ntr/core/route"
	"github.com/LOVECHEN/ntr/netstack"
)

// Options 是 TUN 入站配置(与 stub.go 同名同字段,两态可链接)。
type Options struct {
	Name         string           // 接口名;空 = 平台默认(linux ntr-tun0)
	Address      []string         // TUN 网卡地址 CIDR(如 10.9.9.1/24);至少一个
	MTU          int              // 默认 1500
	Resolver     route.Resolver   // 非 nil 且 HijackDNS 命中 → DNS 就地应答(不走出站),防 DNS 泄漏
	HijackDNS    []netip.AddrPort // 劫持的 DNS 目标;含 unspecified:53 = 任意 :53(空=不劫持)
	AutoRoute    bool             // 自动配 split-default 路由把流量导入 tun(footgun,仅 Linux,需 CAP_NET_ADMIN + iproute2)
	RouteExclude []string         // auto-route 时经原网关直连的 IP(每个 proxy 出站的 server 地址,防回环)
}

// Inbound 是 TUN 入站,自身即 netstack.Handler。
type Inbound struct {
	opts     Options
	out      endpoint.Outbound
	st       *netstack.Stack
	resolver route.Resolver
	hijack   []netip.AddrPort
}

var _ netstack.Handler = (*Inbound)(nil)

// NewInbound 构造(未打开设备)。
func NewInbound(o Options, out endpoint.Outbound) (*Inbound, error) {
	if len(o.Address) == 0 {
		return nil, errors.New("tun: 需至少一个 address(CIDR)")
	}
	if out == nil {
		return nil, errors.New("tun: 需绑定一个出站")
	}
	return &Inbound{opts: o, out: out, resolver: o.Resolver, hijack: o.HijackDNS}, nil
}

// Run 打开 TUN 设备、建栈、启动,阻塞至 ctx 取消。listen 仅作日志标签(TUN 无监听端口)。
func (h *Inbound) Run(ctx context.Context, _ string) error {
	var prefixes []netip.Prefix
	for _, s := range h.opts.Address {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("tun: 解析 address %q:%w", s, err)
		}
		prefixes = append(prefixes, p)
	}
	mtu := uint32(h.opts.MTU)
	if mtu == 0 {
		mtu = 1500
	}
	var primary netip.Prefix
	if len(prefixes) > 0 {
		primary = prefixes[0]
	}
	dev, err := openDevice(deviceName(h.opts.Name), mtu, primary)
	if err != nil {
		return err
	}
	if h.opts.AutoRoute { // 自动把默认流量导入 tun(split-default + 排除代理服务器 IP);footgun,失败即中止
		undo, aerr := autoRoute(deviceName(h.opts.Name), h.opts.RouteExclude)
		if aerr != nil {
			_ = dev.Close()
			return fmt.Errorf("tun auto-route:%w", aerr)
		}
		defer undo()
	}
	st, err := netstack.New(dev, netstack.Options{MTU: mtu, Addresses: prefixes}, h)
	if err != nil {
		_ = dev.Close()
		return err
	}
	h.st = st
	if err := st.Start(); err != nil {
		_ = st.Close()
		return err
	}
	<-ctx.Done()
	_ = st.Close()
	return ctx.Err()
}

// HandleTCP:合成的 TCP 流 → 拨出站 + 双向中继。
func (h *Inbound) HandleTCP(conn net.Conn, dst netip.AddrPort) {
	if h.shouldHijack(dst) { // DNS-hijack::53 就地由 resolver 应答(TCP DNS,2 字节长度前缀)
		h.serveDNSTCP(conn)
		return
	}
	up, err := h.out.DialStream(context.Background(), toSocksaddr(dst))
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = relay.Relay(connStream{conn}, up)
}

// HandleUDP:合成的 UDP 连接(单目标)→ 拨出站 UDP + 双向中继。
func (h *Inbound) HandleUDP(conn net.Conn, dst netip.AddrPort) {
	if h.shouldHijack(dst) { // DNS-hijack::53 就地由 resolver 应答(UDP 每包一次)
		h.serveDNSUDP(conn)
		return
	}
	d := toSocksaddr(dst)
	pc, err := h.out.DialPacket(context.Background(), d)
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = relay.RelayPacket(&tunUDPConn{Conn: conn, dst: d}, pc)
}

func toSocksaddr(a netip.AddrPort) addr.Socksaddr { return addr.FromIPPort(a) }

// connStream 把 net.Conn 抬成 link.Stream(补 Unwrap)。
type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

// tunUDPConn 把 gVisor 合成的单目标 UDP net.Conn 适配成 NTR link.PacketConn(dst 恒为握手目标)。
type tunUDPConn struct {
	net.Conn
	dst addr.Socksaddr
}

var _ link.PacketConn = (*tunUDPConn)(nil)

func (c *tunUDPConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	b.Reset()
	n, err := c.Conn.Read(b.ExtendTail(b.Tailroom()))
	if err != nil {
		return addr.Socksaddr{}, err
	}
	b.Truncate(n)
	return c.dst, nil
}

func (c *tunUDPConn) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error {
	_, err := c.Conn.Write(b.Bytes())
	return err
}

func (c *tunUDPConn) SetDeadline(t time.Time) error { return c.Conn.SetDeadline(t) }
func (c *tunUDPConn) Unwrap() any                   { return c.Conn }
