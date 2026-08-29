// Package route 定义方向无关的隧道端点与分流引擎接口(承设计第 2 章 §2.4、第 8 章)。
//
// 一个 Session 无论谁 dial 下层都同时实现 StreamSource(AcceptStream 侧)与
// StreamSink(OpenStream 侧),router 只见 Source/Sink、零方向特判。反向代理
// (bridge/portal)不是特判:角色反转 = 叶子 Mode(Dial/Listen)× compile 推导的
// SubstreamRole(Open/Accept)两个正交量的交叉,没有全局 tag map。
package route

import (
	"context"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

// Mode 是物理握手方向 —— 叶子上的数据字段,作者可写。
type Mode uint8

const (
	Dial   Mode = iota // 叶子主动拨下层 TCP/QUIC
	Listen             // 叶子被动收下层
)

// SubstreamRole 是逻辑 mux 子流角色 —— 作者不可手填,由 compile 从叶子 Mode +
// 隧道边方向推导,只出现在 Plan 里。
type SubstreamRole uint8

const (
	RoleOpen   SubstreamRole = iota // OpenStream 侧
	RoleAccept                      // AcceptStream 侧
)

// StreamSource 产出入站流 + 其不可变 Metadata。
type StreamSource interface {
	Accept(ctx context.Context) (link.Stream, *endpoint.Metadata, error)
}

// StreamSink 按 Metadata 拨出一条流。
type StreamSink interface {
	Dial(ctx context.Context, md *endpoint.Metadata) (link.Stream, error)
}

// Mount 是一个 live site。Mode 是数据不是角色。
type Mount interface {
	Mode() Mode
	Sessions(ctx context.Context) (<-chan link.Session, error)
}

// Engine 是分流引擎:只读冻结后的 Metadata getter,首个命中 = min-ordinal,
// 返回目标出站的 tag。字节路径零规则逻辑;规则匹配在 admission 期一次。
type Engine interface {
	Route(md *endpoint.Metadata) (target string, err error)
}
