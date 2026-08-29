//go:build with_tun

// Package netstack 是 NTR 原生的用户态协议栈:把 L3 IP 形态(core/link.Device)合成成 L4 连接,
// 每条经 Handler 交出去。这是 NTR 架构里「Device 必经 netstack 合成才产生 Stream/PacketConn」那一层的落点。
//
// 它只做 IP → 连接 的合成,不管落地策略(拨哪个出站、怎么 relay)—— 那是 Handler 的事。与 NTR 出站
// protocol-agnostic 配合,任意协议都能承接 netstack 合成出的连接(这正是「任何协议都能 TUN」的基石)。
//
// 实现:基于 gVisor(NTR 已依赖 gvisor.dev/gvisor)的 tcpip 栈 —— channel 链路端点桥接 Device,
// tcp/udp Forwarder 拦截【发往任意目标】的连接、CreateEndpoint 合成,gonet 适配成 net.Conn。
// gViser 原语是地道用法,非移植他人整包。需 -tags with_tun 编入(默认瘦二进制不拉 gVisor tcpip 转发)。
package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	ntrbuf "github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

const nicID tcpip.NICID = 1

// Handler 承接 netstack 合成出的连接。TCP/UDP 各给一条 net.Conn + 原始目标(应用本想到达的地址)。
// UDP 每条对应一个唯一 4 元组(单目标)。落地(拨出站 + relay)由实现决定。
type Handler interface {
	HandleTCP(conn net.Conn, dst netip.AddrPort)
	HandleUDP(conn net.Conn, dst netip.AddrPort)
}

// Options 是 netstack 配置。MTU 取自设备;Addresses 是 TUN 接口自身地址(挂到 NIC,配合混杂模式接管全部流量)。
type Options struct {
	MTU       uint32
	Addresses []netip.Prefix
}

// Stack 是一台跑着的用户态协议栈,绑在一个 link.Device 上。
type Stack struct {
	dev     link.Device
	stack   *stack.Stack
	ep      *channel.Endpoint
	handler Handler
	ctx     context.Context
	cancel  context.CancelFunc
}

// New 构造(未启动)。Start 后开始收发泵 + 合成连接。
func New(dev link.Device, opts Options, handler Handler) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        false, // 本机地址的包也要转发出去(TUN 接管全部),不本地环回
	})
	mtu := opts.MTU
	if mtu == 0 {
		mtu = dev.MTU()
	}
	ep := channel.New(2048, mtu, "")

	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("netstack: CreateNIC:%v", err)
	}
	// 混杂 + 欺骗:接管发往【任意目标】的包、允许以任意源回包 —— TUN 的本质。
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("netstack: 混杂模式:%v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("netstack: 欺骗模式:%v", err)
	}
	for _, p := range opts.Addresses {
		var pn tcpip.NetworkProtocolNumber
		if p.Addr().Is4() {
			pn = ipv4.ProtocolNumber
		} else {
			pn = ipv6.ProtocolNumber
		}
		pa := tcpip.ProtocolAddress{
			Protocol:          pn,
			AddressWithPrefix: tcpip.AddrFromSlice(p.Addr().AsSlice()).WithPrefix(),
		}
		_ = s.AddProtocolAddress(nicID, pa, stack.AddressProperties{})
	}
	// 默认路由:v4/v6 全量走本 NIC。
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	// SACK 提升 TCP 吞吐。
	sackOpt := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)

	ctx, cancel := context.WithCancel(context.Background())
	st := &Stack{dev: dev, stack: s, ep: ep, handler: handler, ctx: ctx, cancel: cancel}
	st.installForwarders()
	return st, nil
}

// Start 启动收发泵(阻塞式泵在 goroutine 里跑,Start 立即返回)。
func (s *Stack) Start() error {
	go s.inboundLoop()
	go s.outboundLoop()
	return nil
}

// Close 停栈、停泵、关设备。
func (s *Stack) Close() error {
	s.cancel()
	s.stack.Close()
	s.ep.Close()
	return s.dev.Close()
}

// inboundLoop:设备读一个 IP 包 → 注入协议栈。
func (s *Stack) inboundLoop() {
	for {
		b := ntrbuf.New()
		if err := s.dev.ReadPacket(b); err != nil {
			b.Release()
			s.cancel()
			return
		}
		data := b.Bytes()
		if len(data) < 1 {
			b.Release()
			continue
		}
		var pn tcpip.NetworkProtocolNumber
		switch data[0] >> 4 {
		case 4:
			pn = ipv4.ProtocolNumber
		case 6:
			pn = ipv6.ProtocolNumber
		default:
			b.Release()
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		s.ep.InjectInbound(pn, pkb)
		pkb.DecRef()
		b.Release()
	}
}

// outboundLoop:协议栈出一个 IP 包 → 写回设备。
func (s *Stack) outboundLoop() {
	for {
		pkb := s.ep.ReadContext(s.ctx)
		if pkb == nil {
			return
		}
		view := pkb.ToView()
		b := ntrbuf.New()
		_, _ = b.Write(view.AsSlice())
		_ = s.dev.WritePacket(b)
		b.Release()
		view.Release()
		pkb.DecRef()
	}
}

// installForwarders 装 TCP/UDP 转发器:拦截发往任意目标的新连接,合成 net.Conn 交 Handler。
func (s *Stack) installForwarders() {
	tcpFwd := tcp.NewForwarder(s.stack, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true) // 发 RST
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, ep)
		go s.handler.HandleTCP(conn, dstOf(id)) // relay 会阻塞,另起 goroutine,不卡协议栈
	})
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s.stack, func(r *udp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}
		conn := gonet.NewUDPConn(&wq, ep)
		go s.handler.HandleUDP(conn, dstOf(id))
	})
	s.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
}

// dstOf 取转发请求里的【原始目标】(应用本想到达的 LocalAddress:LocalPort)。
func dstOf(id stack.TransportEndpointID) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	return netip.AddrPortFrom(ip.Unmap(), id.LocalPort)
}
