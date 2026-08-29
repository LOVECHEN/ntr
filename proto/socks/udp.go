package socks

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// SOCKS 也实现 UDP ASSOCIATE 的服务端 UDP 能力(本地入站收 UDP 应用流量)。多目标由上游 udpnat 处理。
var _ proxy.PacketConnServer = (*Proxy)(nil)

var errShortUDP = errors.New("socks: UDP 包过短")

// handleUDPAssoc 处理 SOCKS5 UDP ASSOCIATE:建中继 UDP socket、回中继地址,返回载 socket 的
// udpAssocStream + Network=UDP 的 Request(交 relayPacket→udpNAT)。控制 TCP conn 一断即关 UDP
// socket —— UDP 走独立 socket,靠控制流存活维持关联(标准 SOCKS UDP 生命周期)。
func (p *Proxy) handleUDPAssoc(below link.Stream) (link.Stream, *proxy.Request, error) {
	var bindIP net.IP
	if la, ok := below.LocalAddr().(*net.TCPAddr); ok {
		bindIP = la.IP
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		_, _ = below.Write(reply(0x01)) // general failure
		return nil, nil, err
	}
	port := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	ip := bindIP
	if ip == nil || ip.IsUnspecified() {
		ip = net.IPv4zero // 回 0.0.0.0 → 客户端用连 TCP 时的代理 IP 发 UDP
	}
	if _, err := below.Write(replyAddr(0x00, ip, port)); err != nil {
		_ = udp.Close()
		return nil, nil, err
	}
	// 控制 TCP conn 读到 EOF/错误(客户端关连接)→ 关 UDP socket → 上游 udpNAT 自然收尾。
	go func() {
		_, _ = io.Copy(io.Discard, below)
		_ = udp.Close()
	}()
	return &udpAssocStream{Stream: below, udp: udp},
		&proxy.Request{Cred: cred.Ref{ID: cred.Ambient}, Network: endpoint.NetworkUDP, Command: CmdUDPAssoc, Dst: addr.Socksaddr{}}, nil
}

// ServerPacketConn 实现 proxy.PacketConnServer:从 udpAssocStream 取出中继 socket,适配成多目标 PacketConn。
func (p *Proxy) ServerPacketConn(hs link.Stream, _ addr.Socksaddr) (link.PacketConn, error) {
	as, ok := hs.(*udpAssocStream)
	if !ok {
		return nil, errors.New("socks: ServerPacketConn 需 UDP ASSOCIATE 建立的 stream")
	}
	return &socksUDPConn{udp: as.udp}, nil
}

// udpAssocStream 是 UDP ASSOCIATE 的载体 stream:携带中继 UDP socket + 控制 TCP conn。
// 不承载 payload(UDP 走独立 socket);Close 关两者。
type udpAssocStream struct {
	link.Stream // 控制 TCP conn
	udp         *net.UDPConn
}

func (s *udpAssocStream) Close() error {
	_ = s.udp.Close()
	return s.Stream.Close()
}
func (s *udpAssocStream) Unwrap() any { return s.Stream }

// socksUDPConn 把中继 UDP socket 抬成多目标 link.PacketConn:解/封 SOCKS-UDP 头,记客户端地址回程。
type socksUDPConn struct {
	udp    *net.UDPConn
	mu     sync.Mutex
	client *net.UDPAddr // 首包学到的客户端 UDP 源地址(回程目标)
}

var _ link.PacketConn = (*socksUDPConn)(nil)

// ReadPacket 收一个客户端 UDP 包,剥 SOCKS-UDP 头 [RSV(2)][FRAG][ATYP][ADDR][PORT],b 留 payload,返回目标。
//
// 中继 socket 是非连接式(收任意来源),故:① 首包锁定客户端地址,之后【丢弃非该客户端的包】
// (防他人往中继端口打包劫持回程);② 头解析失败/分片【丢弃并继续】,单个坏包不拖垮整条关联。
// 只有 socket 级错误(关闭)才返回。
func (c *socksUDPConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	for {
		b.Reset()
		n, src, err := c.udp.ReadFromUDP(b.ExtendTail(b.Tailroom()))
		if err != nil {
			return addr.Socksaddr{}, err // socket 级错误 = 致命
		}
		b.Truncate(n)

		c.mu.Lock()
		if c.client == nil {
			c.client = src
		} else if !c.client.IP.Equal(src.IP) || c.client.Port != src.Port {
			c.mu.Unlock()
			continue // 非关联客户端 → 丢弃
		}
		c.mu.Unlock()

		p := b.Bytes()
		if len(p) < 4 || p[2] != 0 { // 过短 / 分片(FRAG!=0)→ 丢弃继续
			continue
		}
		dst, hdrLen, err := parseUDPAddr(p[3:])
		if err != nil {
			continue // 坏地址头 → 丢弃继续
		}
		b.Advance(3 + hdrLen) // 剥 RSV+FRAG+ATYP+ADDR+PORT,留 payload
		return dst, nil
	}
}

// WritePacket 把 b(payload)封 SOCKS-UDP 头后发回客户端 UDP 地址(dst=响应来源目标)。
func (c *socksUDPConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	c.mu.Lock()
	cli := c.client
	c.mu.Unlock()
	if cli == nil {
		return errors.New("socks: 尚未收到客户端 UDP 包,无回程地址")
	}
	hdr := encodeUDPHeader(dst)
	copy(b.ExtendHeader(len(hdr)), hdr)
	_, err := c.udp.WriteToUDP(b.Bytes(), cli)
	return err
}

func (c *socksUDPConn) Close() error                  { return c.udp.Close() }
func (c *socksUDPConn) LocalAddr() net.Addr           { return c.udp.LocalAddr() }
func (c *socksUDPConn) SetDeadline(t time.Time) error { return c.udp.SetDeadline(t) }
func (c *socksUDPConn) Unwrap() any                   { return nil }

// replyAddr 构造带具体中继地址的 SOCKS5 应答。
func replyAddr(rep byte, ip net.IP, port uint16) []byte {
	out := []byte{version, rep, 0x00}
	if ip4 := ip.To4(); ip4 != nil {
		out = append(out, atypIPv4)
		out = append(out, ip4...)
	} else {
		out = append(out, atypIPv6)
		out = append(out, ip.To16()...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	return append(out, pb[:]...)
}

// parseUDPAddr 从字节切片解 [ATYP][ADDR][PORT],返回目标 + 消耗字节数。
func parseUDPAddr(p []byte) (addr.Socksaddr, int, error) {
	if len(p) < 1 {
		return addr.Socksaddr{}, 0, errShortUDP
	}
	switch p[0] {
	case atypIPv4:
		if len(p) < 1+4+2 {
			return addr.Socksaddr{}, 0, errShortUDP
		}
		ip := netip.AddrFrom4([4]byte(p[1:5]))
		return addr.FromIPPort(netip.AddrPortFrom(ip, binary.BigEndian.Uint16(p[5:7]))), 1 + 4 + 2, nil
	case atypIPv6:
		if len(p) < 1+16+2 {
			return addr.Socksaddr{}, 0, errShortUDP
		}
		ip := netip.AddrFrom16([16]byte(p[1:17]))
		return addr.FromIPPort(netip.AddrPortFrom(ip, binary.BigEndian.Uint16(p[17:19]))), 1 + 16 + 2, nil
	case atypDomain:
		if len(p) < 2 {
			return addr.Socksaddr{}, 0, errShortUDP
		}
		dl := int(p[1])
		if len(p) < 2+dl+2 {
			return addr.Socksaddr{}, 0, errShortUDP
		}
		return addr.FromFqdn(string(p[2:2+dl]), binary.BigEndian.Uint16(p[2+dl:2+dl+2])), 2 + dl + 2, nil
	default:
		return addr.Socksaddr{}, 0, ErrAtyp
	}
}

// encodeUDPHeader 构造 SOCKS-UDP 头 [RSV(2)=0][FRAG=0][ATYP][ADDR][PORT]。
func encodeUDPHeader(dst addr.Socksaddr) []byte {
	out := []byte{0, 0, 0} // RSV(2) + FRAG(1)
	switch {
	case dst.IsFqdn():
		out = append(out, atypDomain, byte(len(dst.Fqdn)))
		out = append(out, dst.Fqdn...)
	case dst.Addr.Is4():
		out = append(out, atypIPv4)
		a := dst.Addr.As4()
		out = append(out, a[:]...)
	default:
		out = append(out, atypIPv6)
		a := dst.Addr.As16()
		out = append(out, a[:]...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], dst.Port)
	return append(out, pb[:]...)
}
