// Package muxcool(出站)把 Xray 的 Mux.cool 多路复用接成 NTR 出站:包一个 base 出站,经自研
// muxcool.ClientWorker 把多条 DialStream 复用到少数几条 base 承载连接上 —— 与 Xray 的 mux(mux.cool)
// 服务端线级互通。
//
// 布局同 sing-mux 出站(outbound/mux):承载连接 = base.DialStream 拨【Xray 魔术目标 v1.mux.cool:9527】
// 建的一条完整 base 协议流(vless/vmess/trojan/…),其上每条子流写 Mux.cool 的 New/Keep/End 帧(真实
// 目标在 New 帧里)。故对 base 协议零改动、对 Mux.cool 线格式零改动。复用项目已有的 muxcool 编解码
// (原为 reverse 而写,帧格式即 Xray 的),这里只加"客户端载体管理"(按并发挑/建载体、子流计数回收)。
//
// TCP 走 ClientWorker.OpenStream;UDP-over-mux(全锥,按 target 复用子流)走 ClientWorker.NewPacketConn
// (两者皆为项目 muxcool 既有能力)。服务端侧解复用见 service/muxcool.go(TCP+UDP 子流都能落地)。
package muxcool

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	mc "github.com/LOVECHEN/ntr/muxcool"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

// muxCoolDest —— Xray mux 载体连接的固定目标(base 出站拨到这里建承载)。
var muxCoolDest = addr.FromFqdn("v1.mux.cool", 9527)

// defaultConcurrency —— 单条载体承载的最大并发子流数(对齐 Xray mux concurrency 默认 8)。
const defaultConcurrency = 8

var _ endpoint.Outbound = (*Outbound)(nil)

// Outbound 是 Mux.cool 出站:管理若干 base 承载(每条最多 concurrency 条子流),按容量挑/建。
type Outbound struct {
	base        endpoint.Outbound
	concurrency int

	mu       sync.Mutex
	carriers []*carrier
}

// carrier —— 一条 base 承载连接上的 Mux.cool 客户端 + 其活跃子流计数。
type carrier struct {
	w    *mc.ClientWorker
	live int
}

// NewOutbound 用 base 出站构造 Mux.cool 出站。concurrency<=0 用默认 8。
func NewOutbound(base endpoint.Outbound, concurrency int) (*Outbound, error) {
	if base == nil {
		return nil, errors.New("muxcool: 需绑定一个 base 出站")
	}
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	return &Outbound{base: base, concurrency: concurrency}, nil
}

// DialStream 开一条 Mux.cool 子流承载 dst(TCP)。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	c, err := o.acquire(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := c.w.OpenStream(mc.NetworkTCP, toMuxAddr(dst), dst.Port)
	if err != nil {
		o.release(c) // 建子流失败(载体已坏),回退计数并弃之
		o.drop(c)
		return nil, err
	}
	return &countedStream{Conn: conn, o: o, c: c}, nil
}

// DialPacket 开一条 Mux.cool UDP-over-mux 连接(XUDP 全锥):承载上按 target 复用/新建 UDP 子流
// (muxcool.ClientWorker.NewPacketConn 已实现),每包按其 dst 发 UDP New/Keep 帧,回程带 source。
func (o *Outbound) DialPacket(ctx context.Context, _ addr.Socksaddr) (link.PacketConn, error) {
	c, err := o.acquire(ctx)
	if err != nil {
		return nil, err
	}
	return &muxPacket{pc: c.w.NewPacketConn(), o: o, c: c}, nil
}

// Close 关闭所有载体。
func (o *Outbound) Close() error {
	o.mu.Lock()
	cs := o.carriers
	o.carriers = nil
	o.mu.Unlock()
	for _, c := range cs {
		_ = c.w.Close()
	}
	return nil
}

// acquire 取一条有容量的载体(优先复用),否则新建一条承载连接 + ClientWorker。
func (o *Outbound) acquire(ctx context.Context) (*carrier, error) {
	o.mu.Lock()
	// 剔除已死载体,并找一条未满的。
	live := o.carriers[:0]
	var pick *carrier
	for _, c := range o.carriers {
		if !c.w.IsActive() {
			_ = c.w.Close()
			continue
		}
		live = append(live, c)
		if pick == nil && c.live < o.concurrency {
			pick = c
		}
	}
	o.carriers = live
	if pick != nil {
		pick.live++
		o.mu.Unlock()
		return pick, nil
	}
	o.mu.Unlock()

	// 无可用载体:拨一条新承载连接(base 拨魔术目标)+ 起 ClientWorker。
	stream, err := o.base.DialStream(ctx, muxCoolDest)
	if err != nil {
		return nil, err
	}
	w := mc.NewClientWorker(stream)
	go func() { _ = w.Run() }()
	c := &carrier{w: w, live: 1}
	o.mu.Lock()
	o.carriers = append(o.carriers, c)
	o.mu.Unlock()
	return c, nil
}

// release 递减载体的活跃子流计数。
func (o *Outbound) release(c *carrier) {
	o.mu.Lock()
	if c.live > 0 {
		c.live--
	}
	o.mu.Unlock()
}

// drop 从池里摘除一条坏载体并关闭。
func (o *Outbound) drop(c *carrier) {
	o.mu.Lock()
	out := o.carriers[:0]
	for _, x := range o.carriers {
		if x != c {
			out = append(out, x)
		}
	}
	o.carriers = out
	o.mu.Unlock()
	_ = c.w.Close()
}

// toMuxAddr 把 NTR addr.Socksaddr 转成 muxcool.Address(域名/IP)。
func toMuxAddr(dst addr.Socksaddr) mc.Address {
	if dst.IsFqdn() {
		return mc.Address{IsDomain: true, Domain: dst.Fqdn}
	}
	return mc.Address{IP: net.IP(dst.Addr.AsSlice())}
}

// countedStream 包 Mux.cool 子流:Close 时递减载体计数(容量回收)。
type countedStream struct {
	net.Conn
	o    *Outbound
	c    *carrier
	once sync.Once
}

var _ link.Stream = (*countedStream)(nil)

func (s *countedStream) Close() error {
	err := s.Conn.Close()
	s.once.Do(func() { s.o.release(s.c) })
	return err
}

func (s *countedStream) Unwrap() any { return nil }

// muxPacket 把 muxcool 的全锥 net.PacketConn 适配成 NTR link.PacketConn(多目标,每包自带 dst)。
// WritePacket 按包的 dst 发(全锥);ReadPacket 回填各子流的 source。Close 回收载体计数。
type muxPacket struct {
	pc   net.PacketConn
	o    *Outbound
	c    *carrier
	once sync.Once
}

var _ link.PacketConn = (*muxPacket)(nil)

func (m *muxPacket) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	b.Reset()
	n, src, err := m.pc.ReadFrom(b.ExtendTail(b.Tailroom()))
	if err != nil {
		return addr.Socksaddr{}, err
	}
	b.Truncate(n)
	return netAddrToNTR(src), nil
}

func (m *muxPacket) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	_, err := m.pc.WriteTo(b.Bytes(), ntrToNetAddr(dst))
	return err
}

func (m *muxPacket) Close() error {
	err := m.pc.Close()
	m.once.Do(func() { m.o.release(m.c) })
	return err
}

func (m *muxPacket) LocalAddr() net.Addr           { return m.pc.LocalAddr() }
func (m *muxPacket) SetDeadline(t time.Time) error { return m.pc.SetDeadline(t) }
func (m *muxPacket) Unwrap() any                   { return nil }

// ntrToNetAddr 把 addr.Socksaddr 转 net.Addr:IP→*net.UDPAddr;域名→hostPortAddr(String=host:port)。
func ntrToNetAddr(d addr.Socksaddr) net.Addr {
	if d.IsFqdn() {
		return hostPortAddr(net.JoinHostPort(d.Fqdn, strconv.Itoa(int(d.Port))))
	}
	return &net.UDPAddr{IP: net.IP(d.Addr.AsSlice()), Port: int(d.Port)}
}

// netAddrToNTR 把回程 net.Addr 转 addr.Socksaddr。
func netAddrToNTR(a net.Addr) addr.Socksaddr {
	if ua, ok := a.(*net.UDPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ua.IP); ok {
			return addr.FromIPPort(netip.AddrPortFrom(ip.Unmap(), uint16(ua.Port)))
		}
	}
	host, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return addr.Socksaddr{}
	}
	port, _ := strconv.Atoi(portStr)
	if ip, err := netip.ParseAddr(host); err == nil {
		return addr.FromIPPort(netip.AddrPortFrom(ip, uint16(port)))
	}
	return addr.FromFqdn(host, uint16(port))
}

// hostPortAddr 是携带 "host:port"(可含域名)的 net.Addr。
type hostPortAddr string

func (hostPortAddr) Network() string  { return "udp" }
func (h hostPortAddr) String() string { return string(h) }
