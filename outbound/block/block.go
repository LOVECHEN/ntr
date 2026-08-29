// Package block 是「阻断」内置出站(mihomo Reject / Xray Blackhole 对位;承设计 §3.5、§8.1.3
// 内置出站表)。它把流量丢进黑洞,不建任何上游连接。两种模式:
//
//	reject(默认):DialStream/DialPacket 直接返回错误 —— 上游 relay 收到错误即关客户端连接(RST 式立拒)。
//	drop:返回一个「黑洞」连接 —— 写全丢弃、读阻塞到关闭 —— 客户端连上但收不到任何回应(静默吞,耗对端)。
//
// 承 §3.5 line 452「拒绝(可选立即 RST 或静默丢)」。路由 target=block 时对规则引擎零特判(与 direct 同为
// 一等出站名)。协议无感知,不塞任何字段,不碰任何线格式。
package block

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = Outbound{}

// ErrBlocked:reject 模式下出站被策略阻断(上游据此关闭客户端连接)。
var ErrBlocked = errors.New("block: 流量被策略阻断")

// Outbound 是阻断出站。Drop=false(默认)立即拒绝;Drop=true 静默黑洞。
type Outbound struct {
	Drop bool
}

// DialStream:reject 直接报错;drop 返回黑洞流。
func (o Outbound) DialStream(context.Context, addr.Socksaddr) (link.Stream, error) {
	if o.Drop {
		return newHole(), nil
	}
	return nil, ErrBlocked
}

// DialPacket:reject 直接报错;drop 返回黑洞包连接。
func (o Outbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	if o.Drop {
		return newHole(), nil
	}
	return nil, ErrBlocked
}

// hole 是黑洞连接:写全丢弃、读阻塞到关闭。同时满足 link.Stream 与 link.PacketConn。
type hole struct {
	closed chan struct{}
	once   sync.Once
}

var (
	_ link.Stream     = (*hole)(nil)
	_ link.PacketConn = (*hole)(nil)
)

func newHole() *hole { return &hole{closed: make(chan struct{})} }

// Read 阻塞到 Close(客户端发的数据被上游写入 hole 侧的 Write 丢弃,这一侧永不产出 → 客户端收不到回应)。
func (h *hole) Read([]byte) (int, error) {
	<-h.closed
	return 0, net.ErrClosed
}

// Write 丢弃一切,佯称成功(黑洞:吞掉客户端数据不回)。
func (h *hole) Write(p []byte) (int, error) {
	select {
	case <-h.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

// ReadPacket 阻塞到 Close(与 Read 同义,包语义)。
func (h *hole) ReadPacket(*buf.Buffer) (addr.Socksaddr, error) {
	<-h.closed
	return addr.Socksaddr{}, net.ErrClosed
}

// WritePacket 丢弃一切。
func (h *hole) WritePacket(*buf.Buffer, addr.Socksaddr) error {
	select {
	case <-h.closed:
		return net.ErrClosed
	default:
		return nil
	}
}

func (h *hole) Close() error {
	h.once.Do(func() { close(h.closed) })
	return nil
}

func (*hole) LocalAddr() net.Addr                { return blackholeAddr{} }
func (*hole) RemoteAddr() net.Addr               { return blackholeAddr{} }
func (*hole) SetDeadline(time.Time) error        { return nil }
func (*hole) SetReadDeadline(time.Time) error    { return nil }
func (*hole) SetWriteDeadline(time.Time) error   { return nil }
func (*hole) Unwrap() any                        { return nil }

type blackholeAddr struct{}

func (blackholeAddr) Network() string { return "block" }
func (blackholeAddr) String() string  { return "blackhole" }
