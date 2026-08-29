package service

import (
	"context"
	"fmt"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/rule"
)

// RuleRouter 用规则引擎(rule.Engine)按目标 dst 选出站,实现 OutboundResolver(承设计 §8.3)。
// 引擎返回目标出站【名】,再经 Outs 映射到具体 endpoint.Outbound。规则匹配在 admission 期一次、
// 离字节路径;Outs 是编译期冻结的具名出站表(含 direct/block 等内置)。
type RuleRouter struct {
	Engine *rule.Engine
	Outs   map[string]endpoint.Outbound
}

// Resolve 实现 OutboundResolver:Route(dst) → 目标名 → Outs 查表。未知目标名 = 配置错误(编译期
// 本应挡住,此处兜底报错而非静默直连,守「绝不静默误路由」)。
func (r RuleRouter) Resolve(_ context.Context, dst addr.Socksaddr) (endpoint.Outbound, error) {
	target := r.Engine.Route(dst)
	out, ok := r.Outs[target]
	if !ok {
		return nil, fmt.Errorf("route: 规则命中目标出站 %q 未在 outbounds 定义", target)
	}
	return out, nil
}
