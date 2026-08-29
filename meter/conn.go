package meter

import (
	"github.com/LOVECHEN/ntr/core/link"
)

// Conn 包一条 link.Stream:Read 计上行(client→target)、Write 计下行(target→client),经 Meter 稀疏累计。
// 注:包裹后不再是裸 *net.TCPConn,relay 的 splice(ReadFrom)零拷贝对该连接失效 —— 这是计量的诚实代价
// (承设计 §5「splice 互斥是真实路径变化」);仅在开启计量时付,默认关闭零成本。
type Conn struct {
	link.Stream
	m *Meter
}

// Wrap 把 s 包成计量流(m 为该连接的 Meter)。
func Wrap(s link.Stream, m *Meter) link.Stream { return &Conn{Stream: s, m: m} }

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Stream.Read(p)
	c.m.AddUp(n)
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	n, err := c.Stream.Write(p)
	c.m.AddDown(n)
	return n, err
}

// Unwrap 返回被包裹的下层(能力发现;但因计量刻意拦在此层,splice 不再向下透)。
func (c *Conn) Unwrap() any { return c.Stream }
