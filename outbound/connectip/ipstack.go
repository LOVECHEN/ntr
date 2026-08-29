//go:build with_connectip

package connectip

import (
	"context"
	"fmt"
	"net/netip"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
)

// ipStack 是【服务端侧】的用户态协议栈:接收对端经隧道送来的完整 IP 包,
// 用 gvisor 的 TCP/UDP forwarder 把它们【合成回 L4 连接】,再交给 NTR 的出站落地。
//
// 这与客户端侧(wireguard 的 tun/netstack,只提供 Dial)方向相反 —— 那边是
// L4→L3 合成 IP 包,这边是 L3→L4 还原连接。故必须直接用 gvisor,不能复用 tun/netstack。
//
// 关键:开 PromiscuousMode + Spoofing —— 客户端会把包发往【任意】互联网目标地址,
// 栈必须接受非本机地址的包并允许以其为源回包,否则一律丢弃。
type ipStack struct {
	stack *stack.Stack
	ep    *channel.Endpoint
	mtu   uint32
}

const nicID = 1

// newIPStack 建服务端侧协议栈并挂上 TCP/UDP forwarder。
// out 是 NTR 的出站:合成出的每条 L4 连接都经它落地。
func newIPStack(ctx context.Context, mtu uint32, out endpoint.Outbound) (*ipStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(1024, mtu, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("connect-ip: CreateNIC:%v", err)
	}
	// 接受发往任意地址的包 + 允许以任意地址为源(隧道目标是整个互联网)。
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	// 默认路由:两族全网段都走本 NIC。
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	st := &ipStack{stack: s, ep: ep, mtu: mtu}

	// TCP:每条 SYN 触发一次 forwarder 回调,ID().LocalAddress:LocalPort 就是客户端要连的目标。
	tcpFwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dst, ok := toSocksaddr(id.LocalAddress, id.LocalPort)
		if !ok {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		tep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		inner := gonet.NewTCPConn(&wq, tep)
		go func() {
			defer inner.Close()
			up, err := out.DialStream(ctx, dst)
			if err != nil {
				return
			}
			_ = relay.Relay(connStream{inner}, up)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP:同理,每个新五元组触发一次。
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		id := r.ID()
		dst, ok := toSocksaddr(id.LocalAddress, id.LocalPort)
		if !ok {
			return
		}
		var wq waiter.Queue
		uep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			return
		}
		inner := gonet.NewUDPConn(&wq, uep)
		go func() {
			defer inner.Close()
			up, err := out.DialPacket(ctx, dst)
			if err != nil {
				return
			}
			defer up.Close()
			relayUDP(inner, up, dst)
		}()
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return st, nil
}

// Inject 把一个完整 IP 包注入协议栈(隧道 → 栈)。
func (s *ipStack) Inject(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch pkt[0] >> 4 { // IP 版本在首字节高 4 位
	case 4:
		proto = header.IPv4ProtocolNumber
	case 6:
		proto = header.IPv6ProtocolNumber
	default:
		return // 非 IP 包,丢弃
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	})
	s.ep.InjectInbound(proto, pb)
	pb.DecRef()
}

// ReadPacket 从协议栈取一个出站 IP 包(栈 → 隧道),阻塞至有包或 ctx 取消。
func (s *ipStack) ReadPacket(ctx context.Context) ([]byte, bool) {
	pb := s.ep.ReadContext(ctx)
	if pb == nil {
		return nil, false
	}
	data := pb.ToView().AsSlice()
	out := make([]byte, len(data))
	copy(out, data)
	pb.DecRef()
	return out, true
}

// Close 关闭协议栈。
func (s *ipStack) Close() {
	s.ep.Close()
	s.stack.Close()
}

// toSocksaddr 把 gvisor 的地址+端口转成 NTR 的 Socksaddr。
func toSocksaddr(a tcpip.Address, port uint16) (addr.Socksaddr, bool) {
	ip, ok := netip.AddrFromSlice(a.AsSlice())
	if !ok {
		return addr.Socksaddr{}, false
	}
	return addr.FromIPPort(netip.AddrPortFrom(ip.Unmap(), port)), true
}

// relayUDP 在 netstack 合成出的 UDP 连接与 NTR 出站之间双向搬包。
func relayUDP(inner *gonet.UDPConn, up link.PacketConn, dst addr.Socksaddr) {
	done := make(chan struct{}, 2)
	go func() { // 上行:隧道内客户端 → 真实目标
		p := make([]byte, 65535)
		for {
			n, err := inner.Read(p)
			if err != nil {
				done <- struct{}{}
				return
			}
			b := buf.New()
			if _, werr := b.Write(p[:n]); werr != nil {
				b.Release()
				continue
			}
			err = up.WritePacket(b, dst)
			b.Release()
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	go func() { // 下行:真实目标 → 隧道内客户端
		b := buf.New()
		defer b.Release()
		for {
			b.Reset()
			if _, err := up.ReadPacket(b); err != nil {
				done <- struct{}{}
				return
			}
			if _, err := inner.Write(b.Bytes()); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}
