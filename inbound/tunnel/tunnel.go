// Package tunnel 是固定目标端口转发入站:监听端口上每条连接都转发到配置里写死的同一个 target,
// TCP 与 UDP 皆可。对应 xray 的 dokodemo-door(指定 address 形态)、常见的「端口映射 / port-forward」。
//
// 它不解析任何代理协议(下游是裸 TCP/UDP),目标恒为 target,握手信息为零 —— 故与出站协议无关:
// out 由 config 选出,vless/trojan/ss/socks/… 任何出站都能把这条隧道送出去。跨平台(纯 net)。
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/inbound/forward"
)

// Options 是 tunnel 入站配置。
type Options struct {
	Target  string   // 固定目标 host:port(必填)
	Network []string // tcp / udp(空 = 两者都开)
}

// Inbound 是 tunnel 入站。
type Inbound struct {
	out     endpoint.Outbound
	dst     addr.Socksaddr
	tcp     bool
	udp     bool
	nat     *forward.NAT
}

// NewInbound 构造(解析固定目标)。
func NewInbound(o Options, out endpoint.Outbound) (*Inbound, error) {
	if out == nil {
		return nil, errors.New("tunnel: 需绑定一个出站")
	}
	if o.Target == "" {
		return nil, errors.New("tunnel: 需配置 target(固定目标 host:port)")
	}
	host, portStr, err := net.SplitHostPort(o.Target)
	if err != nil {
		return nil, fmt.Errorf("tunnel: 解析 target %q:%w", o.Target, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("tunnel: target 端口非法 %q", portStr)
	}
	tcp, udp := false, false
	if len(o.Network) == 0 {
		tcp, udp = true, true
	}
	for _, n := range o.Network {
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "tcp":
			tcp = true
		case "udp":
			udp = true
		default:
			return nil, fmt.Errorf("tunnel: 未知 network %q(仅 tcp/udp)", n)
		}
	}
	return &Inbound{
		out: out,
		dst: dstOf(host, uint16(port)),
		tcp: tcp,
		udp: udp,
		nat: forward.NewNAT(0),
	}, nil
}

// dstOf 构造目标 Socksaddr:能解析成 IP 就用 IP,否则当域名(交给出站解析)。
func dstOf(host string, port uint16) addr.Socksaddr {
	if ip, err := netip.ParseAddr(host); err == nil {
		return addr.FromIPPort(netip.AddrPortFrom(ip, port))
	}
	return addr.FromFqdn(host, port)
}

// Run 起 TCP/UDP 监听(按配置),阻塞至 ctx 取消。
func (h *Inbound) Run(ctx context.Context, listen string) error {
	errc := make(chan error, 2)
	var running int
	if h.tcp {
		running++
		go func() { errc <- h.serveTCP(ctx, listen) }()
	}
	if h.udp {
		running++
		go func() { errc <- h.serveUDP(ctx, listen) }()
	}
	if running == 0 {
		return errors.New("tunnel: network 为空(tcp/udp 都没开)")
	}
	// 任一支路致命退出即返回(其余随 ctx 收尾)。
	err := <-errc
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return ctx.Err()
	}
	return err
}

func (h *Inbound) serveTCP(ctx context.Context, listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("tunnel: 监听 TCP %s:%w", listen, err)
	}
	context.AfterFunc(ctx, func() { _ = ln.Close() })
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() { _ = forward.Stream(ctx, h.out, c, h.dst) }()
	}
}

func (h *Inbound) serveUDP(ctx context.Context, listen string) error {
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return fmt.Errorf("tunnel: 监听 UDP %s:%w", listen, err)
	}
	context.AfterFunc(ctx, func() { _ = pc.Close() })
	buf := make([]byte, 64*1024)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		// 每个源一条流,固定 dst;回写走同一监听 socket 送回该源(无专属 socket,onClose=nil)。
		open := func() (func([]byte) error, func(), error) {
			return func(p []byte) error { _, e := pc.WriteTo(p, src); return e }, nil, nil
		}
		h.nat.Dispatch(ctx, h.out, src.String(), h.dst, pc.LocalAddr(), open, buf[:n])
	}
}
