package kcptun

import (
	"net"
	"time"

	"github.com/golang/snappy"
)

// compStream 用 snappy 压缩包裹 net.Conn(承 kcptun,nocomp=false 时套在 KCP 与 smux 之间)。
type compStream struct {
	conn net.Conn
	w    *snappy.Writer
	r    *snappy.Reader
}

func (c *compStream) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *compStream) Write(p []byte) (int, error) {
	if _, err := c.w.Write(p); err != nil {
		return 0, err
	}
	if err := c.w.Flush(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *compStream) Close() error                       { return c.conn.Close() }
func (c *compStream) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *compStream) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *compStream) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *compStream) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *compStream) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func newCompStream(conn net.Conn) *compStream {
	return &compStream{conn: conn, w: snappy.NewBufferedWriter(conn), r: snappy.NewReader(conn)}
}
