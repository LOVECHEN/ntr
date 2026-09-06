package service

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
)

// Serve 接受 ln 上的 TCP 连接,逐条抬成 link.Stream + 折叠 Metadata,交给 handler。
// 阻塞至 ln 关闭或 ctx 取消;每连接一 goroutine。这是 admission 边界(承 §3.6):
// Source 在此定,cred/dst 留待协议握手后追认。
func Serve(ctx context.Context, ln net.Listener, h endpoint.InboundHandler) error {
	// ctx 取消 → 关 ln 打断 Accept;Serve 因非 ctx 错误返回时 → close(done) 让看门狗退出(免泄漏)。
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}
		go serveConn(ctx, c, h)
	}
}

func serveConn(ctx context.Context, c net.Conn, h endpoint.InboundHandler) {
	defer c.Close()
	// reaper 兜底(§10):对裸 TCP 开 keepalive —— 未计量的明文 splice 连接拿不到滑动 idle(splice 与
	// per-read 挂钩物理互斥),握手 deadline 只覆盖首字节前;keepalive 是它们【建连后】唯一的死连接廉价保险
	// (对端崩溃/掉线但没发 FIN 时,内核探测失败即断)。已计量连接另有 reaper Seam 3 的滑动 idle。
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(tcpKeepAlivePeriod)
	}
	md := &endpoint.Metadata{
		Network: endpoint.NetworkTCP,
		Source:  sourceAddr(c.RemoteAddr()),
	}
	// 握手/鉴权失败是常态(探测、错凭据),默认不喧哗;NTR_DEBUG=1 或 -debug 时打印源+错误(排查用)。
	// 正常收尾(EOF / 连接已关 —— 客户端断开、UDP 关联结束)不算失败,不打印,免淹没真错误。
	if err := h.HandleStream(ctx, connStream{c}, md); err != nil && !isNormalClose(err) {
		debugf("入站握手/处理失败 src=%s: %v", c.RemoteAddr(), err)
	}
}

// isNormalClose 判连接正常终止(EOF / 连接已关),这类不是"失败",debug 时不喧哗。
func isNormalClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

func sourceAddr(a net.Addr) addr.Socksaddr {
	if ta, ok := a.(*net.TCPAddr); ok {
		return addr.FromIPPort(ta.AddrPort())
	}
	return addr.Socksaddr{}
}

// connStream 把已接受的 net.Conn 抬成 link.Stream,Unwrap 返回底层供能力发现(splice 等)。
type connStream struct{ net.Conn }

func (c connStream) Unwrap() any { return c.Conn }
