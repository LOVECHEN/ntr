// Package dns 是内置「dns」出站(承设计 §3.5 / §8.1.3 内置出站表、§10.1 消费者②):被路由到它的连接
// (客户端 / TUN 发来的 DNS 报文)交 route.Resolver.Exchange 整报文解析,不真去拨目标。UDP:每个数据报
// 一次查询一次应答;TCP:2 字节长度前缀分帧。dst 被忽略(dns 出站按 DNS 语义应答,与目标无关)。
package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/route"
)

var _ endpoint.Outbound = (*Outbound)(nil)

// Outbound 是内置 dns 出站,持一个 route.Resolver。
type Outbound struct {
	r route.Resolver
}

// New 构造。
func New(r route.Resolver) *Outbound { return &Outbound{r: r} }

// DialPacket:UDP DNS —— 每个写入的数据报即一次查询,应答经 ReadPacket 取回。
func (o *Outbound) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	return &packetConn{r: o.r, ctx: ctx, dst: dst, resp: make(chan []byte, 16), closed: make(chan struct{})}, nil
}

// DialStream:TCP DNS —— 2 字节长度前缀分帧,逐条查询逐条应答。
func (o *Outbound) DialStream(ctx context.Context, _ addr.Socksaddr) (link.Stream, error) {
	qr, qw := io.Pipe()
	rr, rw := io.Pipe()
	s := &streamConn{qw: qw, rr: rr}
	go s.loop(ctx, o.r, qr, rw)
	return s, nil
}

// ---- UDP ----

type packetConn struct {
	r      route.Resolver
	ctx    context.Context
	dst    addr.Socksaddr
	resp   chan []byte
	closed chan struct{}
	once   sync.Once
}

func (c *packetConn) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error {
	query := append([]byte(nil), b.Bytes()...)
	go func() {
		m, err := c.r.Exchange(c.ctx, &route.Message{Raw: query})
		if err != nil {
			return // 大声报由 resolver 侧计数;此处丢弃该查询(客户端超时重试)
		}
		select {
		case c.resp <- m.Raw:
		case <-c.closed:
		}
	}()
	return nil
}

func (c *packetConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	select {
	case r := <-c.resp:
		b.Reset()
		_, _ = b.Write(r)
		return c.dst, nil
	case <-c.closed:
		return addr.Socksaddr{}, net.ErrClosed
	}
}

func (c *packetConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *packetConn) LocalAddr() net.Addr        { return dnsAddr{} }
func (c *packetConn) SetDeadline(time.Time) error { return nil }
func (c *packetConn) Unwrap() any                 { return nil }

// ---- TCP ----

type streamConn struct {
	qw   *io.PipeWriter // Write 写查询进来
	rr   *io.PipeReader // Read 读应答出去
	once sync.Once
}

// loop 从 qr 读 2 字节长度分帧的查询,Exchange,把应答按同样分帧写回 rw。
func (s *streamConn) loop(ctx context.Context, r route.Resolver, qr *io.PipeReader, rw *io.PipeWriter) {
	var hdr [2]byte
	for {
		if _, err := io.ReadFull(qr, hdr[:]); err != nil {
			_ = rw.CloseWithError(err)
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(qr, query); err != nil {
			_ = rw.CloseWithError(err)
			return
		}
		m, err := r.Exchange(ctx, &route.Message{Raw: query})
		if err != nil {
			_ = rw.CloseWithError(err)
			return
		}
		binary.BigEndian.PutUint16(hdr[:], uint16(len(m.Raw)))
		if _, err := rw.Write(append(hdr[:], m.Raw...)); err != nil {
			return
		}
	}
}

func (s *streamConn) Write(p []byte) (int, error) { return s.qw.Write(p) }
func (s *streamConn) Read(p []byte) (int, error)  { return s.rr.Read(p) }
func (s *streamConn) Close() error {
	s.once.Do(func() { _ = s.qw.Close(); _ = s.rr.Close() })
	return nil
}
func (s *streamConn) LocalAddr() net.Addr                { return dnsAddr{} }
func (s *streamConn) RemoteAddr() net.Addr               { return dnsAddr{} }
func (s *streamConn) SetDeadline(time.Time) error        { return nil }
func (s *streamConn) SetReadDeadline(time.Time) error    { return nil }
func (s *streamConn) SetWriteDeadline(time.Time) error   { return nil }
func (s *streamConn) Unwrap() any                        { return nil }

type dnsAddr struct{}

func (dnsAddr) Network() string { return "dns" }
func (dnsAddr) String() string  { return "dns-builtin" }
