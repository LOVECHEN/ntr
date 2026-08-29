// Package route 定义路由/解析子系统的【协议无关接口】(承设计 §10.1)。core 只认这里的接口,
// 实现落在 core 外的 dns/(解析器)、rule/(规则引擎)。本文件仅 import netip(stdlib),core 零 import dns/。
package route

import (
	"context"
	"net/netip"
)

// Strategy 是 A/AAAA 选择策略(承 §10.1)。
type Strategy uint8

const (
	StratBoth      Strategy = iota // A + AAAA 都要
	StratPreferV4                  // 优先 IPv4
	StratPreferV6                  // 优先 IPv6
	StratV4Only                    // 仅 IPv4
	StratV6Only                    // 仅 IPv6
)

// Message 是一整份 DNS 线报文(RFC 1035 wire)。Exchange 整报文进出用它;解析细节留在 dns/ 内部,
// 使 core/route 保持 stdlib-only(不 import x/net/dnsmessage)。
type Message struct {
	Raw []byte
}

// Resolver 是 DNS 解析子系统对 core 暴露的接口(承设计 §10.1 的 route.Resolver)。
// 两个消费者:① admission 路由(LookupCached/Lookup,崩点 1);② 内置 dns 出站/监听(Exchange 整报文)。
type Resolver interface {
	// LookupCached 只查缓存、绝不触发上游(崩点 1 非阻塞快路径)。
	LookupCached(host string, s Strategy) (addrs []netip.Addr, ok bool)
	// Lookup 缓存优先;miss 向上游(ctx 带硬 deadline);失败 typed error(绝不把空集当成功)。
	Lookup(ctx context.Context, host string, s Strategy) ([]netip.Addr, error)
	// Exchange 整报文进出 —— 内置 dns 出站/监听用。
	Exchange(ctx context.Context, q *Message) (*Message, error)
	// FakeIPToDomain 反查 fake-ip(Phase 2;MVP 恒返回 ("",false))。
	FakeIPToDomain(ip netip.Addr) (domain string, ok bool)
}
