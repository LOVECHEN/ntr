//go:build linux

// Package transparent 是 Linux 透明代理入站:redirect(iptables REDIRECT + SO_ORIGINAL_DST)与
// tproxy(iptables TPROXY + IP_TRANSPARENT)。两者都从内核恢复「连接的原始目的地」,而不靠任何
// 代理协议握手 —— 因此下游是完全裸的 TCP/UDP,目标由 socket 层给出。恢复出目标后统一交给
// inbound/forward 拨出站 + 中继,故与出站协议无关(任何出站都能承接透明流量)。
//
//	redirect:仅 TCP。listener 普通;每条连接用 getsockopt(SO_ORIGINAL_DST) 取原始目的。
//	tproxy  :TCP + UDP。listener/收包 socket 开 IP_TRANSPARENT;TCP 的原始目的 = 连接本地地址,
//	          UDP 的原始目的来自 recvmsg 的 IP_ORIGDSTADDR 控制消息,回包用 IP_PKTINFO 伪造源地址。
package transparent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/inbound/forward"
)

// Options 是透明入站配置。
type Options struct {
	Mode    string   // redirect | tproxy
	Network []string // tproxy:tcp/udp(空=两者);redirect 恒 tcp
}

// Inbound 是透明入站。
type Inbound struct {
	out  endpoint.Outbound
	mode string
	tcp  bool
	udp  bool
	nat  *forward.NAT
}

// NewInbound 构造。
func NewInbound(o Options, out endpoint.Outbound) (*Inbound, error) {
	if out == nil {
		return nil, errors.New("transparent: 需绑定一个出站")
	}
	in := &Inbound{out: out, mode: o.Mode, nat: forward.NewNAT(0)}
	switch o.Mode {
	case "redirect":
		// REDIRECT 只改写 TCP(UDP 无法可靠恢复原始目的),故恒 TCP。
		in.tcp = true
	case "tproxy":
		if len(o.Network) == 0 {
			in.tcp, in.udp = true, true
		}
		for _, n := range o.Network {
			switch strings.ToLower(strings.TrimSpace(n)) {
			case "tcp":
				in.tcp = true
			case "udp":
				in.udp = true
			default:
				return nil, fmt.Errorf("transparent: 未知 network %q(仅 tcp/udp)", n)
			}
		}
	default:
		return nil, fmt.Errorf("transparent: 未知 mode %q(仅 redirect/tproxy)", o.Mode)
	}
	return in, nil
}

// Run 起监听,阻塞至 ctx 取消。
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
		return errors.New("transparent: network 为空")
	}
	err := <-errc
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return ctx.Err()
	}
	return err
}

// serveTCP:redirect 用普通 listener + SO_ORIGINAL_DST;tproxy 用 IP_TRANSPARENT listener + 本地地址。
func (h *Inbound) serveTCP(ctx context.Context, listen string) error {
	ln, err := h.listenTCP(ctx, listen)
	if err != nil {
		return err
	}
	context.AfterFunc(ctx, func() { _ = ln.Close() })
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		dst, err := h.origDstTCP(c)
		if err != nil {
			_ = c.Close()
			continue
		}
		go func() { _ = forward.Stream(ctx, h.out, c, addr.FromIPPort(dst)) }()
	}
}
