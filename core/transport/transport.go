// Package transport 定义传输层变换器接口(承设计第 3 章 §3.1.1)。
//
// 一个传输层是一个变换器,按产物形状分两型:StreamTransport(Stream→Stream:
// TLS/REALITY/ShadowTLS/Vision/WS/gRPC/H2/SplitHTTP)与 SessionTransport(产
// Session:QUIC(Packet→Session)/mux(Stream→Session))。分型是编译期收益——
// Go 编译器保证不能把产 Session 的层塞进要 Stream 的槽。ClientWrap/ServerWrap 由叶子
// Mount.Mode 沿栈向上决定,同一个 Descriptor 覆盖入站与出站。
package transport

import (
	"context"
	"net"

	"github.com/LOVECHEN/ntr/core/link"
)

// StreamTransport 是 Stream→Stream 变换器。
type StreamTransport interface {
	ClientWrap(ctx context.Context, below link.Stream) (link.Stream, error)
	ServerWrap(ctx context.Context, below link.Stream) (link.Stream, error)
}

// BaseTransport 是【基础传输】:自建到 server 的底层可靠流(替代默认 TCP),供 UDP-base 传输
// (mkcp 等 —— 底层是 UDP datagram,自带可靠层/握手,不 wrap 已有 stream 而是【创建】base 流)。
// 占 BandBase,居栈底。出站用 DialBase 拨(替代 TCP 拨号),入站用 ListenBase(UDP 监听 + accept
// 出可靠流,喂给正常代理栈)。栈里 base 之上仍可叠 StreamTransport(如 tls)与终端协议。
type BaseTransport interface {
	DialBase(ctx context.Context, server string) (link.Stream, error)
	ListenBase(ctx context.Context, listen string) (BaseListener, error)
}

// BaseListener 是 BaseTransport 的服务端监听:每 Accept 出一条可靠 link.Stream(如一条 KCP 会话),
// 交正常代理栈(HandleStream)—— 与 TCP net.Listener 语义对齐,故核心接入零特判。
type BaseListener interface {
	Accept() (link.Stream, error)
	Close() error
	Addr() net.Addr
}

// SessionTransport 产 Session(QUIC:PacketConn→Session;mux:Stream→Session)。
// base 是下层产物(link.PacketConn 或 link.Stream),按具体实现断言。
type SessionTransport interface {
	ClientUpgrade(ctx context.Context, base any) (link.Session, error)
	ServerUpgrade(ctx context.Context, base any) (link.Session, error)
}
