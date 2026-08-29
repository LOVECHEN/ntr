// Package link 定义四形状数据面(承设计第 2 章 §2.1)——代理连接建模的不可约地基:
//
//	Stream      字节流(TCP 系)
//	PacketConn  代理寻址的数据报(目标可为域名)
//	Session     流工厂 + datagram 侧信道(QUIC / mux)
//	Device      L3 IP 包(TUN / WG)
//
// 以及唯一的跨层能力发现入口 GetCapability[T]。本包零依赖(除 net/context/时间与
// 本仓 buf/addr),核心对任何具体协议零 import。
package link

import (
	"context"
	"net"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
)

// Stream 是字节流形状。Unwrap 暴露被本层包裹的下层(用于能力发现),nil = 到底。
type Stream interface {
	net.Conn
	Unwrap() any
}

// TLSConnCarrier 是可选流能力:承载 TLS 的传输层(tls/reality)据此把底层 TLS 连接
// (*crypto/tls.Conn 或 uTLS)暴露给需要它的上层协议 —— 用于 VLESS Vision(要反射进 TLS
// 内部、按记录边界做 splice)。经 GetCapability[TLSConnCarrier](below) 沿 Unwrap 链发现。
type TLSConnCarrier interface {
	TLSConn() net.Conn
}

// PacketConn 是代理寻址的数据报形状:载荷带逻辑目标 Socksaddr(可为域名),
// 一条 assoc 复用多目标。不是 net.PacketConn(那按 wire addr 寻址)。
type PacketConn interface {
	ReadPacket(b *buf.Buffer) (dst addr.Socksaddr, err error)
	WritePacket(b *buf.Buffer, dst addr.Socksaddr) error
	Close() error
	LocalAddr() net.Addr
	SetDeadline(t time.Time) error
	Unwrap() any
}

// Session 是流工厂 + datagram 侧信道,统一 QUIC 连接与所有 mux 会话。
// Datagram 的第二返回值在 mux-only(无 datagram 能力)时为 false。
type Session interface {
	OpenStream(ctx context.Context) (Stream, error)
	AcceptStream(ctx context.Context) (Stream, error)
	Datagram() (PacketConn, bool)
	Close() error
	Unwrap() any
}

// Device 是 L3 IP 包形状(TUN / WireGuard)。没有连接身份,必经 netstack 合成
// 才产生 Stream/PacketConn,故无 Unwrap。
type Device interface {
	ReadPacket(b *buf.Buffer) error
	WritePacket(b *buf.Buffer) error
	MTU() uint32
	Close() error
}

// unwrapper 是"能被剥一层"的内部约定。
type unwrapper interface{ Unwrap() any }

// GetCapability 沿 Unwrap 链自顶向下 type-assert,返回第一个实现 T 的层。
//
// 这是全仓唯一的跨层能力发现入口(承第 2 章 §2.2.1):上层从此零 unsafe/零 reflect,
// 拿不到能力返回 (zero,false),调用方据此 typed error 大声报,绝不静默退化。
func GetCapability[T any](s any) (T, bool) {
	for s != nil {
		if v, ok := s.(T); ok {
			return v, true
		}
		u, ok := s.(unwrapper)
		if !ok {
			break
		}
		s = u.Unwrap()
	}
	var zero T
	return zero, false
}
