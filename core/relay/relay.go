// Package relay 在两条 link.Stream 间双向搬字节(承设计第 1 章职责 2:转发)。
//
// ★协议无关:relay 只认 link.Stream,不知道两端是什么协议 —— 这是"协议只是插件"在
// 转发层的落点。字节路径用池化缓冲(稳态零分配);io.CopyBuffer 在两端都是裸 *net.TCPConn
// 时自动走 ReadFrom(splice,明文直转的零拷贝红利,承 §3.3.4)。
package relay

import (
	"io"
	"sync"

	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

var bufPool = sync.Pool{New: func() any { s := make([]byte, 32*1024); return &s }}

// Relay 在 a、b 间双向搬字节,直到任一方向结束,然后拆掉两端并等另一方向收尾。
//
// 注:当前是"首个方向结束即关两端"的简单收尾;半关(half-close)语义与 idle 超时回收
// 交给第 10 章的 reaper 生命周期(本函数先保证不泄漏 goroutine)。
func Relay(a, b link.Stream) error {
	errc := make(chan error, 2)
	go func() { errc <- copyStream(b, a) }() // a -> b
	go func() { errc <- copyStream(a, b) }() // b -> a

	err := <-errc // 首个方向结束(EOF 时 io.Copy 返回 nil)
	_ = a.Close()
	_ = b.Close() // 关两端,解阻塞另一方向的读
	<-errc        // 等另一方向收尾,不泄漏 goroutine
	return err
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
