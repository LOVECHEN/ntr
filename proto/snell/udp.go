package snell

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv45"
	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv6"
)

// snell 实现 UDP-over-stream 的多目标 PacketConn(每 frame 自带 target,同 trojan)。v4/v5 与 v6
// 帧/命令逐字节相同(仅 chunk 层不同),故此处以接口统一两代引擎,零版本 switch(除建会话那一处)。
var (
	_ proxy.PacketConnServer = (*Proxy)(nil)
	_ proxy.PacketConnClient = (*Proxy)(nil)
)

var errUDPTooLarge = errors.New("snell: UDP 数据报超缓冲")

// udpServerSession / udpClientSession 抽象两代引擎的 UDP 会话(方法签名一致 → 结构接口自动满足)。
type udpServerSession interface {
	ReadFrom() (target string, data []byte, err error)
	WriteTo(srcIP net.IP, srcPort uint16, data []byte) error
	Close() error
}
type udpClientSession interface {
	WriteTo(target string, data []byte) error
	ReadFrom() (srcIP net.IP, srcPort uint16, data []byte, err error)
	Close() error
}

var (
	_ udpServerSession = (*snellv6.ServerPacketConn)(nil)
	_ udpServerSession = (*snellv45.ServerPacketConn)(nil)
	_ udpClientSession = (*snellv6.ClientPacketConn)(nil)
	_ udpClientSession = (*snellv45.ClientPacketConn)(nil)
)

// ServerPacketConn 从 UDP 握手捕获的 udpCarrier 取出 snellv6 ServerPacketConn,适配成多目标 link.PacketConn。
func (p *Proxy) ServerPacketConn(hs link.Stream, _ addr.Socksaddr) (link.PacketConn, error) {
	c, ok := hs.(*udpCarrier)
	if !ok {
		return nil, errors.New("snell: ServerPacketConn 需 UDP 握手建立的 stream")
	}
	return &snellUDPConn{pc: c.pc, below: c.Stream}, nil
}

// udpCarrier 是 UDP 握手结果的载体 stream:携带两代引擎之一的 ServerPacketConn(接口)。
type udpCarrier struct {
	link.Stream
	pc udpServerSession
}

func (c *udpCarrier) Unwrap() any { return c.Stream }

// snellUDPConn 把 ServerPacketConn 抬成多目标 link.PacketConn:每个客户端 UDP frame
// 自带 target(域名/IP),响应按来源写回。多目标由上游 udpNAT 分发到多条单目标出站。
type snellUDPConn struct {
	pc    udpServerSession
	below link.Stream
}

var _ link.PacketConn = (*snellUDPConn)(nil)

// ReadPacket 读一个客户端 UDP 数据报,b 留 payload,返回其 target。
func (c *snellUDPConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	target, data, err := c.pc.ReadFrom()
	if err != nil {
		return addr.Socksaddr{}, err
	}
	dst, err := parseTarget(target)
	if err != nil {
		return addr.Socksaddr{}, err
	}
	b.Reset()
	if len(data) > b.Tailroom() {
		return addr.Socksaddr{}, errUDPTooLarge
	}
	copy(b.ExtendTail(len(data)), data)
	return dst, nil
}

// WritePacket 把 b(payload)封 snell UDP 响应 frame 写回客户端(src=dst,响应来源)。
func (c *snellUDPConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	ip, port := socksaddrToIP(dst)
	return c.pc.WriteTo(ip, port, b.Bytes())
}

func (c *snellUDPConn) Close() error                  { return c.pc.Close() }
func (c *snellUDPConn) LocalAddr() net.Addr           { return c.below.LocalAddr() }
func (c *snellUDPConn) SetDeadline(t time.Time) error { return c.below.SetDeadline(t) }
func (c *snellUDPConn) Unwrap() any                   { return nil }

// DialPacketConn 实现 proxy.PacketConnClient:发 CmdUDP 握手,返回单目标 client UDP packetConn
// (NTR udpNAT 已按 dst 拆成单目标,故每会话固定一个 dst;每包封 request frame(target=dst))。
func (p *Proxy) DialPacketConn(_ context.Context, below link.Stream, _ []byte, dst addr.Socksaddr) (link.PacketConn, error) {
	var pc udpClientSession
	var err error
	if p.isV45() {
		pc, err = (&snellv45.Client{PSK: p.cfg.PSK}).DialUDPOver(below)
	} else {
		pc, err = (&snellv6.Client{PSK: p.cfg.PSK, ChaCha: p.cfg.ChaCha, Mode: p.cfg.Mode}).DialUDPOver(below)
	}
	if err != nil {
		return nil, err
	}
	return &snellClientUDPConn{pc: pc, below: below, dst: dst}, nil
}

// snellClientUDPConn 单目标(dst 固定)client UDP packetConn。
type snellClientUDPConn struct {
	pc    udpClientSession
	below link.Stream
	dst   addr.Socksaddr
}

var _ link.PacketConn = (*snellClientUDPConn)(nil)

// ReadPacket 读一个响应数据报(单目标:src 恒为 dst)。
func (c *snellClientUDPConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	_, _, data, err := c.pc.ReadFrom()
	if err != nil {
		return addr.Socksaddr{}, err
	}
	b.Reset()
	if len(data) > b.Tailroom() {
		return addr.Socksaddr{}, errUDPTooLarge
	}
	copy(b.ExtendTail(len(data)), data)
	return c.dst, nil
}

// WritePacket 把 b(payload)封 request frame(target=dst)发到 snell 服务端。
func (c *snellClientUDPConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	return c.pc.WriteTo(dst.String(), b.Bytes())
}

func (c *snellClientUDPConn) Close() error                  { return c.pc.Close() }
func (c *snellClientUDPConn) LocalAddr() net.Addr           { return c.below.LocalAddr() }
func (c *snellClientUDPConn) SetDeadline(t time.Time) error { return c.below.SetDeadline(t) }
func (c *snellClientUDPConn) Unwrap() any                   { return nil }

// parseTarget 把 snell UDP frame 的 "host:port" 解成 Socksaddr(IP 字面量 → IP 形态,否则域名)。
func parseTarget(target string) (addr.Socksaddr, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return addr.Socksaddr{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return addr.Socksaddr{}, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return addr.FromIPPort(netip.AddrPortFrom(ip, uint16(port))), nil
	}
	return addr.FromFqdn(host, uint16(port)), nil
}

// socksaddrToIP 把响应目标转成 IP(snell 响应 frame 只支持 IP 形式)。IP 形态直用;域名(罕见)
// 解析首个 IP 作响应来源。
func socksaddrToIP(dst addr.Socksaddr) (net.IP, uint16) {
	if dst.IsIP() {
		return dst.Addr.AsSlice(), dst.Port
	}
	if ips, err := net.LookupIP(dst.Fqdn); err == nil && len(ips) > 0 {
		return ips[0], dst.Port
	}
	return net.IPv4zero, dst.Port
}
