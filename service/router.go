package service

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/route"
	"github.com/LOVECHEN/ntr/rule"
)

// routeResolveTimeout 是崩点1 按需解析的硬 deadline(admission 期、仅缓存 miss 时;失败即回退纯域名匹配)。
const routeResolveTimeout = 2 * time.Second

// RuleRouter 用规则引擎(rule.Engine)按目标 dst 选出站,实现 OutboundResolver(承设计 §8.3)。
// 引擎返回目标出站【名】,再经 Outs 映射到具体 endpoint.Outbound。规则匹配在 admission 期一次、
// 离字节路径;Outs 是编译期冻结的具名出站表(含 direct/block 等内置)。
//
// fake-ip:若 dst 是伪 IP(Fake 反查命中),先换回真域名再路由 —— 这样只见 IP 的连接(TUN 捕获、
// IP 直连)也能命中 domain/geosite/rule-set 规则;换域名后返回一个「拨号时用域名替换伪 IP」的出站包装,
// 使真实拨号走域名(由 direct 真解析 / upstream 透传域名),伪 IP 绝不出本机。
type RuleRouter struct {
	Engine   *rule.Engine
	Outs     map[string]endpoint.Outbound
	Fake     func(netip.Addr) (string, bool) // 伪 IP → 域名(nil=未启用 fake-ip)
	Finder   rule.ProcessFinder              // 源→进程反查(nil=禁用 process 规则)
	Resolver route.Resolver                  // 崩点1:域名目标按需解析真 IP 供 ip-cidr/geoip 匹配(nil=不解析,ip 类维度对域名不命中)
}

// Resolve 实现 OutboundResolver:纯 dst 路由(无源上下文,process 规则不参与)。ctx 可带嗅探协议(protocol 规则)。
func (r RuleRouter) Resolve(ctx context.Context, dst addr.Socksaddr) (endpoint.Outbound, error) {
	return r.route(ctx, dst, netip.AddrPort{}, "tcp", sniffedProtoFrom(ctx))
}

// ResolveConn 实现 ConnResolver:带 client 源地址(供 process 规则)+ ctx 里的嗅探协议(供 protocol 规则)。
func (r RuleRouter) ResolveConn(ctx context.Context, dst addr.Socksaddr, src netip.AddrPort, network string) (endpoint.Outbound, error) {
	return r.route(ctx, dst, src, network, sniffedProtoFrom(ctx))
}

// route 是共用核心:fake-ip 换域名 →(有 ip 规则时)按需解析真 IP → RouteConnIPs → 目标名 → Outs 查表。
// 未知目标名 = 配置错误(编译期本应挡住,此处兜底报错而非静默直连,守「绝不静默误路由」)。
func (r RuleRouter) route(ctx context.Context, dst addr.Socksaddr, src netip.AddrPort, network, proto string) (endpoint.Outbound, error) {
	routeDst := dst
	if r.Fake != nil && dst.IsIP() {
		if domain, ok := r.Fake(dst.Addr); ok {
			routeDst = addr.FromFqdn(domain, dst.Port) // 伪 IP → 域名:既用于路由,也用于拨号
		}
	}
	// 崩点1:域名目标 + 配了 ip-cidr/geoip 规则 + 有 resolver → 按需解析真 IP 供 ip 类维度匹配。
	// 只喂路由决策;拨号 dst 一律不变(仍走域名,伪 IP/域名不出本机)。
	var ips []netip.Addr
	if routeDst.IsFqdn() && r.Resolver != nil && r.Engine.HasIPRules() {
		ips = r.resolveForRouting(ctx, routeDst.Fqdn)
	}
	target := r.Engine.RouteConnIPs(routeDst, ips, src, network, proto, r.Finder)
	out, ok := r.Outs[target]
	if !ok {
		return nil, fmt.Errorf("route: 规则命中目标出站 %q 未在 outbounds 定义", target)
	}
	if routeDst != dst { // 发生了 fake-ip 换域名:包装出站,拨号时用域名替换调用方传入的伪 IP
		return domainRewriteOutbound{inner: out, dst: routeDst}, nil
	}
	return out, nil
}

// resolveForRouting 为路由 ip-cidr/geoip 解析域名真 IP(崩点1):先查缓存(非阻塞快路径);miss 才带短
// deadline 实解析(离字节路径、每 TTL 一次,走 LookupReal 绕过 fake 合成取真 IP)。失败/超时 → nil
// (ip 类维度对该域名不命中,回退纯域名匹配,不崩不泄漏)。返回的 IP 只喂路由决策,拨号 dst 不变。
func (r RuleRouter) resolveForRouting(ctx context.Context, host string) []netip.Addr {
	if ips, ok := r.Resolver.LookupCached(host, route.StratBoth); ok {
		return ips
	}
	rctx, cancel := context.WithTimeout(ctx, routeResolveTimeout)
	defer cancel()
	ips, err := r.Resolver.LookupReal(rctx, host, route.StratBoth)
	if err != nil {
		return nil
	}
	return ips
}

// domainRewriteOutbound 把拨号目标固定为握手期换算出的域名 dst,忽略调用方传入的伪 IP。
type domainRewriteOutbound struct {
	inner endpoint.Outbound
	dst   addr.Socksaddr
}

func (o domainRewriteOutbound) DialStream(ctx context.Context, _ addr.Socksaddr) (link.Stream, error) {
	return o.inner.DialStream(ctx, o.dst)
}

func (o domainRewriteOutbound) DialPacket(ctx context.Context, _ addr.Socksaddr) (link.PacketConn, error) {
	return o.inner.DialPacket(ctx, o.dst)
}
