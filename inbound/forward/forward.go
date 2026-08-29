// Package forward 是各「已知目标」入站(tunnel / redirect / tproxy / …)共享的出站侧中继核心。
//
// 分工:这些入站各自只负责【怎样拿到一条下游连接 + 它要去的 dst】—— tunnel 从配置取固定目标、
// redirect 从 SO_ORIGINAL_DST 取、tproxy 从 IP_TRANSPARENT 的原始目的取;而【拨出站 + 双向中继】
// 完全一致,统一落在这里。故三个入站彼此零重复,且与出站协议无关(vless/trojan/ss/socks/… 任何
// 出站都能承接透明流量)—— 正是「协议只是插件」在入站侧的延伸。
package forward

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
)

// Stream 把一条已建立的下游 TCP 连接接到 out 拨出的 dst,双向中继到任一端结束。
// down 出错/结束后两端都会被关闭(relay 负责),故调用方无需再关 down。
func Stream(ctx context.Context, out endpoint.Outbound, down net.Conn, dst addr.Socksaddr) error {
	up, err := out.DialStream(ctx, dst)
	if err != nil {
		_ = down.Close()
		return err
	}
	return relay.Relay(connStream{down}, up)
}

// connStream 把裸 net.Conn 抬成 link.Stream(补 Unwrap)。
type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

// Packet 把一条【单流】下游 link.PacketConn(某个源的 UDP 流)接到 out 拨出的 dst,双向中继。
// 供 UDP 透明/隧道入站在 demux 出单流后调用。
func Packet(ctx context.Context, out endpoint.Outbound, down link.PacketConn, dst addr.Socksaddr) error {
	up, err := out.DialPacket(ctx, dst)
	if err != nil {
		_ = down.Close()
		return err
	}
	return relay.RelayPacket(down, up)
}

// ── UDP NAT ────────────────────────────────────────────────────────────────
// 无连接的 UDP 入站(tunnel / tproxy)都是「一个下游 socket 收到来自多个源的包」的形态:
// 需按源(或源+原始目的)聚成会话,每会话拨一次出站并双向中继,空闲回收。NAT + Flow 把这套
// 通用逻辑收敛在此,tunnel/tproxy 只需实现各自的「读一个包 → 得到 key/dst/回写函数」。

// Flow 是单条 UDP 流在下游侧的 link.PacketConn 视图:
//   - demux 循环用 Push 灌入该流的入站 datagram;
//   - ReadPacket 取出并回报固定 dst(空闲超时则返回错误,触发 relay 拆链);
//   - WritePacket 经 sendBack 把上游回包送回原始源。
type Flow struct {
	dst      addr.Socksaddr
	local    net.Addr
	sendBack func([]byte) error
	in       chan []byte
	idle     time.Duration
	closed   chan struct{}
	once     sync.Once
}

var _ link.PacketConn = (*Flow)(nil)

// Push 把一个入站 datagram 交给该流(拷贝入队;队满则丢,合乎 UDP 语义)。
func (f *Flow) Push(payload []byte) {
	p := make([]byte, len(payload))
	copy(p, payload)
	select {
	case f.in <- p:
	case <-f.closed:
	default: // 队满丢包
	}
}

func (f *Flow) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	t := time.NewTimer(f.idle)
	defer t.Stop()
	select {
	case p := <-f.in:
		b.Reset()
		_, _ = b.Write(p)
		return f.dst, nil
	case <-t.C:
		return addr.Socksaddr{}, errIdle
	case <-f.closed:
		return addr.Socksaddr{}, net.ErrClosed
	}
}

func (f *Flow) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error { return f.sendBack(b.Bytes()) }

func (f *Flow) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *Flow) LocalAddr() net.Addr        { return f.local }
func (f *Flow) SetDeadline(time.Time) error { return nil }
func (f *Flow) Unwrap() any                 { return nil }

// errIdle:空闲超时,让 relay 正常拆链(非异常)。
var errIdle = &timeoutError{}

type timeoutError struct{}

func (*timeoutError) Error() string   { return "forward: udp 流空闲超时" }
func (*timeoutError) Timeout() bool   { return true }
func (*timeoutError) Temporary() bool { return false }

// NAT 按 key 复用 UDP 流:已有则灌包,新 key 则建流 + 起一条会话 goroutine(拨出站 + 中继),
// 会话结束(空闲/出错)自动摘除。所有 UDP 透明/隧道入站共用。
type NAT struct {
	mu    sync.Mutex
	flows map[string]*Flow
	idle  time.Duration
}

// NewNAT 建一个 NAT;idle 为单流空闲回收时限(<=0 用默认 60s)。
func NewNAT(idle time.Duration) *NAT {
	if idle <= 0 {
		idle = 60 * time.Second
	}
	return &NAT{flows: make(map[string]*Flow), idle: idle}
}

// Dispatch 把一个入站 datagram 派发到 key 对应的流:
//   - 已存在:直接 Push;
//   - 不存在:调 open 建【本流专属】的回写函数(及可选清理),建流 + Push,并起会话 goroutine
//     经 out 拨 dst 双向中继,结束后清理并摘除该 key。
//
// open 仅在新流时调用一次(故回写用的 socket / 源地址随流创建、随流回收)——
// tunnel 直接回写共享 UDP socket(onClose=nil),tproxy 则为每流绑定一个透明回写 socket。
func (n *NAT) Dispatch(ctx context.Context, out endpoint.Outbound, key string,
	dst addr.Socksaddr, local net.Addr,
	open func() (sendBack func([]byte) error, onClose func(), err error), payload []byte) {
	n.mu.Lock()
	if f, ok := n.flows[key]; ok {
		n.mu.Unlock()
		f.Push(payload)
		return
	}
	sendBack, onClose, err := open()
	if err != nil {
		n.mu.Unlock()
		if onClose != nil {
			onClose()
		}
		return
	}
	f := &Flow{
		dst: dst, local: local, sendBack: sendBack,
		in: make(chan []byte, 64), idle: n.idle, closed: make(chan struct{}),
	}
	n.flows[key] = f
	n.mu.Unlock()

	f.Push(payload)
	go func() {
		_ = Packet(ctx, out, f, dst)
		n.mu.Lock()
		if n.flows[key] == f {
			delete(n.flows, key)
		}
		n.mu.Unlock()
		_ = f.Close()
		if onClose != nil {
			onClose()
		}
	}()
}
