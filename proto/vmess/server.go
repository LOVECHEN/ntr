package vmess

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// vmessHandshakeTimeout 是【捕获到 relay conn/pc 之前】的最长等待。防 slow-loris 半开握手,也
// 兜住畸形流永不回调导致的 goroutine/fd 泄漏。捕获成功后即清除,以免限制后续 relay 的读。
const vmessHandshakeTimeout = 10 * time.Second

// errMuxUDPUnsupported:UDP 侧多子流(XUDP 多路复用)暂不支持(TCP mux 已由 dispatcher 支持)。
var errMuxUDPUnsupported = errors.New("vmess: UDP 多子流 XUDP 暂不支持(单 UDP 子流已支持)")

var _ proxy.Server = (*Proxy)(nil)

// resultKey 把每次握手的结果 holder 塞进 ctx(共享 service + 并发安全:每调用一份 holder)。
type resultKey struct{}

type result struct {
	mu sync.Mutex // 保护以下(Mux/XUDP 时多子流 goroutine 并发回调,共享同一 holder)
	// UDP 捕获路径(单 UDP 子流):
	captured bool
	pc       N.PacketConn
	dst      M.Socksaddr
	ready    chan struct{} // UDP 捕获时 close(唤醒 ServerHandshake 走 UDP 路径)
	// TCP 派发路径(有 dispatcher 时:每条 TCP 子流后台中继,支持并发 mux):
	dispatcher proxy.StreamDispatcher
	dispatched bool
	dispStart  chan struct{}  // 首条 TCP 子流派发时 close(唤醒 ServerHandshake 走"等全部中继"路径)
	wg         sync.WaitGroup // 追踪所有在途子流中继
	// 无 dispatcher 时的 TCP 单流捕获兜底(理论上 service 恒注入,故一般不走):
	conn net.Conn
}

// markReady 关 ready(幂等,持锁调用)。
func (r *result) markReady() {
	select {
	case <-r.ready:
	default:
		close(r.ready)
	}
}

// captureHandler 喂给 sing-vmess 的 Service:sing 的 HandleMuxConnection 在本 goroutine 跑 recvLoop 持续
// 读 below、把每条子流的载荷喂进 pipe,并【另起 goroutine】按子流调用本回调。故本回调【必须尽快返回】,
// 不能同步 relay(否则卡死 recvLoop 泵下一条子流)。
//
// ★ TCP 子流:交注入的 dispatcher 后台中继(每条一 goroutine)—— 天然支持并发 mux(多条 TCP 子流各自
// 落地),不再拒绝第二条。首条派发时 close(dispStart) 唤醒 ServerHandshake 进入"等承载关闭 + 等所有中继"。
// ★ UDP 子流:仍单流捕获(XUDP 多 UDP 子流暂不支持),交 ServerHandshake 走 packetCarrier 适配。
type captureHandler struct{}

func (captureHandler) NewConnection(ctx context.Context, conn net.Conn, md M.Metadata) error {
	r, ok := ctx.Value(resultKey{}).(*result)
	if !ok {
		return nil
	}
	r.mu.Lock()
	if r.dispatcher != nil {
		if !r.dispatched {
			r.dispatched = true
			close(r.dispStart)
		}
		r.wg.Add(1)
		d, dst := r.dispatcher, md.Destination
		r.mu.Unlock()
		go func() {
			defer r.wg.Done()
			d.DispatchStream(ctx, conn, toNTR(dst)) // 后台双向中继本子流,直到收尾
		}()
		return nil
	}
	// 无 dispatcher 兜底:单流捕获(仅第一条)。
	defer r.mu.Unlock()
	if r.captured {
		_ = conn.Close()
		return errMuxUDPUnsupported
	}
	r.captured, r.conn, r.dst = true, conn, md.Destination
	r.markReady()
	return nil
}

func (captureHandler) NewPacketConnection(ctx context.Context, pc N.PacketConn, md M.Metadata) error {
	r, ok := ctx.Value(resultKey{}).(*result)
	if !ok {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.captured {
		_ = pc.Close()
		return errMuxUDPUnsupported
	}
	r.captured = true
	r.pc = pc
	r.dst = md.Destination
	r.markReady()
	return nil
}

func (captureHandler) NewError(context.Context, error) {}

// ServerHandshake 实现 proxy.Server:用共享 Service 读 VMess 请求头(含 replay 校验),捕获 relay
// conn/pc + 目标,返回承载 payload 的 stream + Request。VMess UUID 鉴权由 sing 内部完成 → Ambient。
//
// ★ 异步捕获:service.NewConnection 对普通 Command=TCP/UDP 会在回调后【立即返回】;对 XUDP/Mux
// (xray 的 vmess UDP 默认走此)则进入 HandleMuxConnection 的 recvLoop【持续不返回】。因此不能同步
// 等它返回,而是把它丢到后台 goroutine,等 ready(首次捕获)或它自己返回(错误/普通路径)或超时。
// 捕获后清 read deadline —— 对 XUDP,后台 recvLoop 要长期读 below 泵子流数据,直到 relay 关闭 below。
func (p *Proxy) ServerHandshake(ctx context.Context, below link.Stream, _ proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	r := &result{
		ready:      make(chan struct{}),
		dispStart:  make(chan struct{}),
		dispatcher: proxy.StreamDispatcherFrom(ctx), // service 注入:有则 TCP 子流走后台派发(支持并发 mux)
	}
	cctx := context.WithValue(ctx, resultKey{}, r)
	// 捕获前设 deadline:畸形/半开流永不回调时,读超时使 NewConnection 出错返回 → 不泄漏。
	_ = below.SetReadDeadline(time.Now().Add(vmessHandshakeTimeout))
	done := make(chan error, 1)
	go func() { done <- p.service.NewConnection(cctx, below, M.Metadata{}) }()

	select {
	case <-r.dispStart: // TCP 派发路径:首条子流已后台中继
		return p.awaitDispatched(below, r, done)
	case <-r.ready: // UDP 捕获路径(或无 dispatcher 的 TCP 兜底)
		return p.captureResult(below, r)
	case err := <-done: // NewConnection 先返回:真错误 或 与信号同刻竞态,补判
		select {
		case <-r.dispStart:
			return p.awaitDispatched(below, r, done)
		case <-r.ready:
			return p.captureResult(below, r)
		default:
			if err != nil {
				return nil, nil, err
			}
			return nil, nil, errors.New("vmess: 未捕获到连接")
		}
	}
}

// awaitDispatched:TCP mux 派发模式 —— 放开读(让 recvLoop 泵后续子流),等承载关闭 + 所有子流中继收尾,
// 返回 ErrHandled(整条连接已在内部处理完毕)。done 可能已被上层 select 消费,故用非阻塞补收。
func (p *Proxy) awaitDispatched(below link.Stream, r *result, done chan error) (link.Stream, *proxy.Request, error) {
	_ = below.SetReadDeadline(time.Time{})
	select {
	case <-done: // 承载(recvLoop)已结束
	default:
		<-done // 等承载关闭:无更多子流
	}
	r.wg.Wait() // 等所有在途子流中继收尾
	return nil, nil, proxy.ErrHandled
}

// captureResult:UDP 单流(或无 dispatcher 的 TCP 单流兜底)—— 返回适配后的 carrier + Request。
func (p *Proxy) captureResult(below link.Stream, r *result) (link.Stream, *proxy.Request, error) {
	_ = below.SetReadDeadline(time.Time{})
	r.mu.Lock()
	pc, conn, dst := r.pc, r.conn, r.dst
	r.mu.Unlock()
	if pc != nil {
		return &packetCarrier{Stream: below, pc: pc},
			&proxy.Request{Cred: cred.Ref{ID: cred.Ambient}, Network: endpoint.NetworkUDP, Dst: toNTR(dst)}, nil
	}
	if conn == nil {
		return nil, nil, errors.New("vmess: 未捕获到连接")
	}
	return &streamWrap{Conn: conn, below: below},
		&proxy.Request{Cred: cred.Ref{ID: cred.Ambient}, Network: endpoint.NetworkTCP, Dst: toNTR(dst)}, nil
}
