// Package reverse 实现反向代理(bridge/portal)—— NTR 的"内网反连"能力,对齐 Xray 的
// app/reverse 形态 A(路由触发、协议无关)。
//
// ★核心架构决定:reverse 是【代理契约之上】的一层,不碰任何协议内部,因此【所有流式代理
// 免修改即支持反连】。它只依赖两个最小契约:
//
//	Handshaker    —— 服务端:过传输层 + 协议握手,交出握手后 stream + 目标(service.ProxyInbound)
//	StreamDialer  —— 客户端:经代理出站拨一条承载 dst 的流(upstream.Outbound / endpoint.Outbound)
//
// Mux.cool 帧作为不透明载荷跑在这些流之上(见 muxcool 包)。谁当隧道(vless/vmess/trojan/
// ss/snell/socks…)由部署决定,reverse 一概不知。
//
//	   内网(NAT 后)                              公网(有公网 IP)
//	┌──────────────────┐                      ┌──────────────────┐
//	│  Bridge          │  ── 主动 dial ──▶     │  Portal          │
//	│  = 代理客户端    │   任意代理隧道        │  = 代理服务端    │
//	│  = Mux.cool 服务端│ ◀═ 反向复用回来 ═══   │  = Mux.cool 客户端│
//	│  落地到本地内网  │                      │  用户从这里接入   │
//	└──────────────────┘                      └──────────────────┘
//
// 角色反转(务必记牢):Bridge 主动拨号,但在 Mux.cool 里是 SERVER(被动读 New、落地、回 Keep/End);
// Portal 是 Mux.cool CLIENT(主动开子流承载用户流量 + 控制子流发心跳)。
package reverse

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/muxcool"
)

// Handshaker 过传输层 + 协议握手,交出握手后 stream + Request(不做 relay)。
// service.ProxyInbound.Handshake 满足它。
type Handshaker interface {
	Handshake(ctx context.Context, s link.Stream, md *endpoint.Metadata) (link.Stream, *proxy.Request, error)
}

// StreamDialer 经代理出站拨一条承载 dst 的流。upstream.Outbound / endpoint.Outbound 满足它。
type StreamDialer interface {
	DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error)
}

// DefaultControlDomain 是控制/内层默认域(仅"目标==控制域"这一约定被使用;可配)。
// 与 muxcool.InternalDomain("reverse")区分:那是【控制子流】域;这是【隧道注册】域。
const DefaultControlDomain = "reverse.ntr"

// netStream 把 mux 子流(net.Conn)抬成 link.Stream 供 relay.Relay。
type netStream struct{ net.Conn }

func (netStream) Unwrap() any { return nil }

// toMuxAddr 把 NTR addr.Socksaddr 转成 Mux.cool 地址。
func toMuxAddr(a addr.Socksaddr) muxcool.Address {
	if a.IsFqdn() {
		return muxcool.Address{IsDomain: true, Domain: a.Fqdn}
	}
	return muxcool.Address{IP: a.Addr.AsSlice()}
}

// toMuxNetwork 把归一化网络转成 Mux.cool 目标网络字节。
func toMuxNetwork(n endpoint.Network) muxcool.TargetNetwork {
	if n == endpoint.NetworkUDP {
		return muxcool.NetworkUDP
	}
	return muxcool.NetworkTCP
}

// directDispatcher 用一个 net.Dialer 把 Bridge 解出的 mux 子流【直连落地】到本地目标
// (Bridge 是其所在内网的出口:落地 = 直连,复用 Dialer 的超时/本地地址/Control 策略)。
type directDispatcher struct {
	ctx    context.Context
	dialer net.Dialer
}

var _ muxcool.Dispatcher = directDispatcher{}

// DialTarget 按 target 直连本地目标(TCP/UDP,UDP 为连接式数据报 conn)。
func (d directDispatcher) DialTarget(network muxcool.TargetNetwork, a muxcool.Address, port uint16) (net.Conn, error) {
	hp := net.JoinHostPort(a.String(), strconv.Itoa(int(port)))
	proto := "tcp"
	if network == muxcool.NetworkUDP {
		proto = "udp"
	}
	return d.dialer.DialContext(d.ctx, proto, hp)
}

// sleepCtx 睡 d 或到 ctx 取消;返回 false 表示 ctx 已取消(应退出)。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
