package service

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/muxcool"
)

// Mux.cool 服务端解复用:任何入站握手若解出目标 == Xray 的 mux 载体魔术目标 v1.mux.cool:9527,该流即
// 一条 Mux.cool 承载连接。此处用 NTR 自研 muxcool.ServerWorker 解出其上的多条子流(New/Keep/End 帧),
// 每条按自带真实目标经统一 relay/udpNAT 落地到出站 —— 与 Xray 的 mux.cool 客户端线级互通。
//
// ★与 sing-mux(service/mux.go)并列:两套 mux 线格式不同(sing-mux vs Xray mux.cool),各认各的魔术
// 目标、各走各的解复用,互不干扰。放 service 复用已有 relay + 出站解析,muxcool 是 gate 内叶子包不违门禁。

// isMuxCoolCarrier 报告握手目标是否为 Xray mux.cool 载体魔术目标 v1.mux.cool:9527。
// vless/vmess 的 Command=Mux 已在协议层翻译成此地址,trojan/ss 直接在线上带此地址 —— 故运行时
// 只看地址即可统一识别所有载体协议,核心保持协议无关。
func isMuxCoolCarrier(dst addr.Socksaddr) bool {
	return dst.Fqdn == muxcool.CarrierFqdn
}

// handleMuxCoolCarrier 把一条 mux.cool 承载 stream 交 muxcool.ServerWorker 解复用,阻塞至承载关闭。
func handleMuxCoolCarrier(ctx context.Context, carrier link.Stream, resolver OutboundResolver) error {
	w := muxcool.NewServerWorker(carrier, muxCoolDispatcher{ctx: ctx, resolver: resolver}, nil)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = w.Close()
		case <-done:
		}
	}()
	err := w.Run()
	close(done)
	return err
}

// muxCoolDispatcher 实现 muxcool.Dispatcher:每条子流按自带真实目标解析出站 → 拨 → 交 ServerWorker
// 中继(TCP 直接是 link.Stream;UDP 把单目标 link.PacketConn 适配成 net.Conn)。
type muxCoolDispatcher struct {
	ctx      context.Context
	resolver OutboundResolver
}

var _ muxcool.Dispatcher = muxCoolDispatcher{}

func (d muxCoolDispatcher) DialTarget(network muxcool.TargetNetwork, a muxcool.Address, port uint16) (net.Conn, error) {
	dst := muxAddrToNTR(a, port)
	out, err := d.resolver.Resolve(d.ctx, dst)
	if err != nil {
		return nil, err
	}
	if network == muxcool.NetworkUDP {
		pc, err := out.DialPacket(d.ctx, dst)
		if err != nil {
			return nil, err
		}
		return &packetNetConn{pc: pc, dst: dst}, nil
	}
	s, err := out.DialStream(d.ctx, dst)
	if err != nil {
		return nil, err
	}
	return s, nil // link.Stream 内嵌 net.Conn
}

// muxAddrToNTR 把 muxcool.Address + port 转成 NTR addr.Socksaddr。
func muxAddrToNTR(a muxcool.Address, port uint16) addr.Socksaddr {
	if a.IsDomain {
		return addr.FromFqdn(a.Domain, port)
	}
	if ip, ok := netip.AddrFromSlice(a.IP); ok {
		return addr.FromIPPort(netip.AddrPortFrom(ip.Unmap(), port))
	}
	return addr.FromFqdn(a.String(), port)
}

// packetNetConn 把单目标 link.PacketConn 适配成 net.Conn(Read/Write = 一个数据报),供 muxcool
// ServerWorker 的 UDP 子流落地用(它按 net.Conn 收发数据报)。
type packetNetConn struct {
	pc  link.PacketConn
	dst addr.Socksaddr
}

var _ net.Conn = (*packetNetConn)(nil)

func (c *packetNetConn) Read(p []byte) (int, error) {
	b := buf.New()
	defer b.Release()
	if _, err := c.pc.ReadPacket(b); err != nil {
		return 0, err
	}
	return copy(p, b.Bytes()), nil
}

func (c *packetNetConn) Write(p []byte) (int, error) {
	b := buf.New()
	defer b.Release()
	if _, err := b.Write(p); err != nil {
		return 0, err
	}
	if err := c.pc.WritePacket(b, c.dst); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetNetConn) Close() error                       { return c.pc.Close() }
func (c *packetNetConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *packetNetConn) RemoteAddr() net.Addr               { return nil }
func (c *packetNetConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *packetNetConn) SetReadDeadline(t time.Time) error  { return c.pc.SetDeadline(t) }
func (c *packetNetConn) SetWriteDeadline(t time.Time) error { return nil }
