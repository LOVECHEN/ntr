package service

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/rule"
)

// RuleRouter 用规则引擎(rule.Engine)按目标 dst 选出站,实现 OutboundResolver(承设计 §8.3)。
// 引擎返回目标出站【名】,再经 Outs 映射到具体 endpoint.Outbound。规则匹配在 admission 期一次、
// 离字节路径;Outs 是编译期冻结的具名出站表(含 direct/block 等内置)。
//
// fake-ip:若 dst 是伪 IP(Fake 反查命中),先换回真域名再路由 —— 这样只见 IP 的连接(TUN 捕获、
// IP 直连)也能命中 domain/geosite/rule-set 规则;换域名后返回一个「拨号时用域名替换伪 IP」的出站包装,
// 使真实拨号走域名(由 direct 真解析 / upstream 透传域名),伪 IP 绝不出本机。
type RuleRouter struct {
	Engine *rule.Engine
	Outs   map[string]endpoint.Outbound
	Fake   func(netip.Addr) (string, bool) // 伪 IP → 域名(nil=未启用 fake-ip)
}

// Resolve 实现 OutboundResolver:Route(dst) → 目标名 → Outs 查表。未知目标名 = 配置错误(编译期
// 本应挡住,此处兜底报错而非静默直连,守「绝不静默误路由」)。
func (r RuleRouter) Resolve(_ context.Context, dst addr.Socksaddr) (endpoint.Outbound, error) {
	routeDst := dst
	if r.Fake != nil && dst.IsIP() {
		if domain, ok := r.Fake(dst.Addr); ok {
			routeDst = addr.FromFqdn(domain, dst.Port) // 伪 IP → 域名:既用于路由,也用于拨号
		}
	}
	target := r.Engine.Route(routeDst)
	out, ok := r.Outs[target]
	if !ok {
		return nil, fmt.Errorf("route: 规则命中目标出站 %q 未在 outbounds 定义", target)
	}
	if routeDst != dst { // 发生了 fake-ip 换域名:包装出站,拨号时用域名替换调用方传入的伪 IP
		return domainRewriteOutbound{inner: out, dst: routeDst}, nil
	}
	return out, nil
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
