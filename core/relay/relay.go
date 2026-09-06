// Package relay 在两条 link.Stream 间双向搬字节(承设计第 1 章职责 2:转发)。
//
// ★协议无关:relay 只认 link.Stream,不知道两端是什么协议 —— 这是"协议只是插件"在
// 转发层的落点。字节路径用池化缓冲(稳态零分配);io.CopyBuffer 在两端都是裸 *net.TCPConn
// 时自动走 ReadFrom(splice,明文直转的零拷贝红利,承 §3.3.4)。
package relay

import (
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

var bufPool = sync.Pool{New: func() any { s := make([]byte, 32*1024); return &s }}

// halfCloseIdleNanos 是半关后反向仍活时的尾部 idle(reaper Seam 2,§10;进程级,config 经 SetHalfCloseIdle
// 设,一进程一配置)。0 = 用 defaultHalfCloseIdle。
var halfCloseIdleNanos atomic.Int64

const defaultHalfCloseIdle = 30 * time.Second

// SetHalfCloseIdle 由 config 在 Build 时设置半关尾部 idle(≤0 = 回落默认)。reload 幂等。
func SetHalfCloseIdle(d time.Duration) { halfCloseIdleNanos.Store(int64(d)) }

func halfCloseIdle() time.Duration {
	if v := halfCloseIdleNanos.Load(); v > 0 {
		return time.Duration(v)
	}
	return defaultHalfCloseIdle
}

// Relay 在 a、b 间双向搬字节,直到任一方向结束,再拆两端并等另一方向收尾。
//
// reaper Seam 2(§10)半关:首方向【EOF】(err==nil,即一端发了 FIN)时,不立即全关,而是对另一端
// CloseWrite 传 FIN(半关)、保留反向 copy 继续,并对反向源 arm 一次尾部 idle(halfCloseIdle);反向也
// 结束或 idle 触发则全关。★探不到 CloseWrite 能力(某些包装流 / mux 子流)→ 退回「关两端」(诚实降级)。
// 首方向【非 EOF 错】→ 保持全关(错误不宜半关续传)。半关的 idle 只在这一个冷事件 arm 一次,不在 per-read
// 热路径挂钩 —— active 反向仍走 splice 直到期限,不碰 copyStream 的 0-alloc/ReadFrom 红利。
func Relay(a, b link.Stream) error {
	type res struct {
		err error
		ab  bool // true = a->b 方向(读 a 写 b)先结束
	}
	errc := make(chan res, 2)
	go func() { errc <- res{copyStream(b, a), true} }()  // a -> b
	go func() { errc <- res{copyStream(a, b), false} }() // b -> a

	first := <-errc
	if first.err == nil { // 首方向 EOF:该方向【源】读到 FIN;把 FIN 传给另一端,反向续传
		other := b // 首方向 a->b(读 a EOF)→ 仍活的是 b(既要传 FIN 又要继续被反向读)
		if !first.ab {
			other = a
		}
		if cw, ok := link.GetCapability[interface{ CloseWrite() error }](other); ok {
			_ = cw.CloseWrite()                                        // 半关:传 FIN,不全关
			_ = other.SetReadDeadline(time.Now().Add(halfCloseIdle())) // 反向尾部 idle(反向源正是 other)
			<-errc                                                     // 反向 EOF 或 idle 触发
			_ = a.Close()
			_ = b.Close()
			return first.err
		}
	}
	// 非 EOF 错,或探不到 CloseWrite:退回「关两端」(诚实降级)。
	_ = a.Close()
	_ = b.Close() // 关两端,解阻塞另一方向的读
	<-errc        // 等另一方向收尾,不泄漏 goroutine
	return first.err
}

func copyStream(dst, src link.Stream) error {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	_, err := io.CopyBuffer(dst, src, *bp)
	return err
}

// RelayPacket 在两条 link.PacketConn 间双向搬 datagram,直到任一方向结束。
// 逐包用同一块池化缓冲(Reset 复用,稳态零分配);dst 由源方 ReadPacket 给出,
// WritePacket 原样带过去(单目标时两端都忽略,多目标时透传)。
func RelayPacket(a, b link.PacketConn) error {
	errc := make(chan error, 2)
	go func() { errc <- copyPacket(b, a) }()
	go func() { errc <- copyPacket(a, b) }()
	err := <-errc
	_ = a.Close()
	_ = b.Close()
	<-errc
	return err
}

func copyPacket(dst, src link.PacketConn) error {
	b := buf.New()
	defer b.Release()
	for {
		b.Reset()
		to, err := src.ReadPacket(b)
		if err != nil {
			return err
		}
		if err := dst.WritePacket(b, to); err != nil {
			return err
		}
	}
}
