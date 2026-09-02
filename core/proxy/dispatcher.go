package proxy

import (
	"context"
	"errors"
	"net"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
)

// StreamDispatcher 把一条【已解密的】mux 子流(net.Conn + 真实目标 + 归属)经配置的出站中继落地。
//
// 由 service 通过握手 ctx 注入,专供【传输库在内部自行解复用 mux】的协议(如 vmess:sing-vmess 的
// HandleMuxConnection 直接把一条承载连接拆成多条子流回调,而非把承载交回核心按地址识别)。这类协议
// 的插件够不到出站解析器(协议门禁禁止 proto import service),故 service 把中继能力作为【数据】经 ctx
// 递给它 —— 不破坏"协议只是插件"(插件仍不 import service,只调一个接口)。
//
// who 是握手鉴出的归属(顶层 users 的 BillID 或 Ambient):承载对核心不可见,接入闸 + 按用户计量只能
// 落在子流上(一子流 = 一连接,字节记到 who),故必须由插件把鉴权结果随子流一起交回。
//
// 每条子流独立并发中继;插件应在自己的 goroutine 里调用(不要在解复用 recvLoop 的回调里同步调用,
// 否则中继阻塞会卡死 recvLoop 泵下一条子流)。
type StreamDispatcher interface {
	DispatchStream(ctx context.Context, conn net.Conn, dst addr.Socksaddr, who cred.Ref)
}

type dispatcherKey struct{}

// WithStreamDispatcher 把 dispatcher 放进 ctx(service 在调 ServerHandshake 前注入)。
func WithStreamDispatcher(ctx context.Context, d StreamDispatcher) context.Context {
	return context.WithValue(ctx, dispatcherKey{}, d)
}

// StreamDispatcherFrom 取出注入的 dispatcher(无则 nil,插件据此回落到单流捕获路径)。
func StreamDispatcherFrom(ctx context.Context) StreamDispatcher {
	d, _ := ctx.Value(dispatcherKey{}).(StreamDispatcher)
	return d
}

// ErrHandled 表示 ServerHandshake 已在内部把整条连接处理完毕(所有 mux 子流均已中继落地),
// 调用方不得再中继或二次收尾。service 见此按"成功完成"处理。
var ErrHandled = errors.New("proxy: connection handled internally")
