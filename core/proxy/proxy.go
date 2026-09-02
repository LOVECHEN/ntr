// Package proxy 定义协议插件的统一契约(承设计第 2 章:协议是插件式变换器,核心零 import
// 具体协议)。inbound / relay / 路由等核心代码【只认这里的接口】,永不 switch 具体协议 ——
// 这是"协议只是插件"的类型层落点。
//
// 每个协议的 Descriptor.Build 产物实现 Server(服务端握手)和/或 Client(客户端握手);
// 核心通过这两个接口驱动任意协议,零 diff、零特判。
package proxy

import (
	"context"
	"net"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

// Request 是服务端握手的产物:冻结的目标 + 归属凭据 + 网络 + 命令。协议无关 —— 下游
// relay/路由只见 Request,不知道是哪个协议产的。
//
// Network 是【归一化】的 TCP/UDP(各协议把私有命令值映射到它),下游据此选流/包路径,
// 不许看 Command 裸值(那是协议私有);Command 仅作协议内部/取证细节保留。
type Request struct {
	Dst     addr.Socksaddr
	Cred    cred.Ref
	Network endpoint.Network
	Command byte // 协议私有命令(vless UDP=2 / trojan/socks UDP=3 …);判 TCP/UDP 用 Network
}

// Authenticator 把协议凭据材料映射到已绑定的 cred.Ref。协议把它读到的 key 交上来
// (VLESS 的 UUID、Snell 的 clientID …),admission 负责解析成归属。scheme = 协议名。
type Authenticator interface {
	// Auth 按 scheme 特定的 key 解析凭据;(_,false) = 未匹配(调用方决定 reject / Unmatched / Ambient)。
	Auth(scheme string, key []byte) (cred.Ref, bool)
}

// Server 是协议的服务端侧(入站)。
type Server interface {
	// ServerHandshake 在 below(传输层已应用)上跑服务端握手,经 auth 解析凭据,
	// 返回承载 payload 的 link.Stream + Request(dst + cred + command)。
	ServerHandshake(ctx context.Context, below link.Stream, auth Authenticator) (link.Stream, *Request, error)
}

// Client 是协议的客户端侧(出站)。
type Client interface {
	// ClientHandshake 在 below 上跑客户端握手,出示凭据 key(VLESS UUID / Snell PSK …),
	// 到达 dst,返回承载 payload 的 link.Stream。
	ClientHandshake(ctx context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.Stream, error)
}

// PacketConnServer 是可选能力:当 ServerHandshake 产出 Network=UDP 的 Request 时,把承载
// datagram 分帧的 stream 适配成 link.PacketConn。dst = Request.Dst(单目标语义;多目标由
// mux/XUDP 或多流承载,后续接入)。核心靠能力发现调用,零协议 switch。
type PacketConnServer interface {
	ServerPacketConn(below link.Stream, dst addr.Socksaddr) (link.PacketConn, error)
}

// PacketConnClient 是可选能力:发起 UDP 关联(写 UDP 请求头),返回单目标 link.PacketConn。
type PacketConnClient interface {
	DialPacketConn(ctx context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.PacketConn, error)
}

// PacketServer 是可选能力:协议的 UDP 【入站】是【原生 datagram】(Shadowsocks 等)——
// 客户端直发加密 UDP 到监听端口,没有先导 stream(故不走 ServerHandshake / PacketConnServer)。
// 核心把绑好的 UDP socket 交给它;它自己按源做 NAT、解密、解目标,对每条【逻辑 UDP 流】回调 sink
// 交出一条已解密的多目标 link.PacketConn,由核心 udpNAT 落地到出站。阻塞至 ctx 取消或 socket 关闭。
// 是 NativePacketConnClient 的服务端镜像 —— 二者共同补齐原生 UDP 协议的两个方向。
type PacketServer interface {
	ServePacket(ctx context.Context, pc net.PacketConn, sink func(link.PacketConn)) error
}

// NativePacketConnClient 是可选能力:协议的 UDP 是【原生 datagram】(Shadowsocks 等)——
// 每包独立加密直发上游 UDP 端口,【不 over stream】。它自建到 server 的 UDP socket,不需要
// 下层 stream。upstream.DialPacket 优先探测此能力:命中则不拨无用的 TCP below(否则对纯原生
// UDP 协议每次关联都白白多握一次 TCP)。与 PacketConnClient 互斥择一 —— 这正是"插件系统可以
// 有多套实现"的落点:UDP-over-stream 协议(VLESS/VMess/Trojan)实现前者,原生 UDP 协议实现后者。
type NativePacketConnClient interface {
	DialNativePacketConn(ctx context.Context, server string, key []byte, dst addr.Socksaddr) (link.PacketConn, error)
}

// CredentialCodec 是可选能力:插件声明如何把用户配置的口令 secret 变成线上凭据 ——
// 这是"插件注册自己的凭据需求"(承第 1 章设计)的落点。客户端出示的 key 与服务端登记的
// 鉴权键可以【不同】:如 Trojan,客户端出示明文口令、服务端登记 SHA224(口令) 的 hex。
// 组装根(cmd/config)靠能力发现调用它,自身零协议 switch;不实现 = 无 per-user 凭据(如
// Snell 用端口 PSK、SOCKS 本地 no-auth)。
type CredentialCodec interface {
	// ClientKey 由口令派生"客户端出示给上游的 key"(传给 ClientHandshake)。
	ClientKey(secret string) ([]byte, error)
	// AuthKey 由口令派生"服务端登记进 Authenticator 的键"(与 ServerHandshake 读到的 key 同源)。
	AuthKey(secret string) ([]byte, error)
}

// AuthGate 是可选能力:鉴权对该协议是"可选"的(socks / http / gost 这类无凭据也能跑的入站)。
// 协议自身不知道、也不该知道配置里有没有给这口配 users —— 那是零协议 switch 的边界;
// 由装配侧在登记完 per-user 凭据后告知:配了 → 握手必须出示凭据、未匹配即拒;没配 → 保持 no-auth。
type AuthGate interface {
	SetAuthRequired(required bool)
}
