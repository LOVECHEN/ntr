package trusttunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/internal/ipresolve"
)

// TrustTunnel UDP 复用(_udp2)线格式(对齐 TrustTunnel 规范 / mihomo transport/trusttunnel,禁改):
// CONNECT 到魔术 authority "_udp2"(User-Agent "<os> _udp2"),回 200 后流上双向是长度前缀帧,地址只许 IP:
//
//	客户端 → 服务端:[len u32][源 16B=0][源端口=0][目的 16B][目的端口][appName 长 u8][appName][payload]
//	服务端 → 客户端:[len u32][源 16B][源端口][目的 16B=0][目的端口=0][payload]
//
// len = 其后全部字节数;16B 地址:IPv4 = 12 字节 0 + 4 字节地址(非 ::ffff 映射;::1 特判为 IPv6)。
const (
	udpMagic  = "_udp2"
	appName   = "ntr"
	addrBlock = 16 + 2 + 16 + 2 // 源 + 源端口 + 目的 + 目的端口
)

var (
	udpUserAgent  = runtime.GOOS + " " + udpMagic
	errUDPTooLong = errors.New("trusttunnel: UDP 帧长度非法")
)

// encodeIP16 把 IP 编成 16 字节(IPv4 前 12 字节为 0)。
func encodeIP16(a netip.Addr) (b [16]byte) {
	a = a.Unmap()
	if a.Is4() {
		v4 := a.As4()
		copy(b[12:], v4[:])
		return b
	}
	return a.As16()
}

// decodeIP16 反解 16 字节地址:前 12 字节为 0 且不是 ::1 → IPv4。
func decodeIP16(b [16]byte) netip.Addr {
	var zero [12]byte
	if [12]byte(b[:12]) == zero && !(b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] == 1) {
		return netip.AddrFrom4([4]byte(b[12:]))
	}
	return netip.AddrFrom16(b)
}

// frameConn 是 _udp2 流上的多目标 link.PacketConn(两端共用;client 决定读写哪种帧)。读侧由后台 goroutine
// 逐帧解析入队,ReadPacket 带 deadline(运行时 udpNAT 每读前 arm 空闲超时);写侧加锁(多目标回写会并发)。
type frameConn struct {
	s      link.Stream
	client bool
	remote net.Addr
	ips    ipresolve.Cache // 帧里地址只许 IP:FQDN 先解析

	in     chan inFrame
	closed chan struct{}
	once   sync.Once
	rerr   error

	wmu      sync.Mutex
	dmu      sync.Mutex
	deadline time.Time
}

type inFrame struct {
	data []byte
	addr addr.Socksaddr
}

var _ link.PacketConn = (*frameConn)(nil)

func newFrameConn(s link.Stream, client bool, remote net.Addr) *frameConn {
	c := &frameConn{s: s, client: client, remote: remote, in: make(chan inFrame, 64), closed: make(chan struct{})}
	go c.readLoop()
	return c
}

// readLoop 逐帧读:客户端读服务端帧(取源地址),服务端读客户端帧(取目的地址、跳过 appName)。
func (c *frameConn) readLoop() {
	defer c.Close()
	var hdr [4 + addrBlock]byte
	for {
		if _, err := io.ReadFull(c.s, hdr[:]); err != nil {
			c.rerr = err
			return
		}
		n := int(binary.BigEndian.Uint32(hdr[:4])) - addrBlock
		var ip [16]byte
		var a addr.Socksaddr
		if c.client { // 源地址在前
			copy(ip[:], hdr[4:20])
			a = addr.FromIPPort(netip.AddrPortFrom(decodeIP16(ip), binary.BigEndian.Uint16(hdr[20:22])))
		} else { // 目的地址在后,另有 appName
			copy(ip[:], hdr[22:38])
			a = addr.FromIPPort(netip.AddrPortFrom(decodeIP16(ip), binary.BigEndian.Uint16(hdr[38:40])))
			var l [1]byte
			if _, err := io.ReadFull(c.s, l[:]); err != nil {
				c.rerr = err
				return
			}
			if _, err := io.CopyN(io.Discard, c.s, int64(l[0])); err != nil {
				c.rerr = err
				return
			}
			n -= 1 + int(l[0])
		}
		if n < 0 || n > 0xffff {
			c.rerr = errUDPTooLong
			return
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(c.s, p); err != nil {
			c.rerr = err
			return
		}
		select {
		case c.in <- inFrame{data: p, addr: a}:
		case <-c.closed:
			return
		}
	}
}

func (c *frameConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	c.dmu.Lock()
	d := c.deadline
	c.dmu.Unlock()
	var timeout <-chan time.Time
	if !d.IsZero() {
		t := time.NewTimer(time.Until(d))
		defer t.Stop()
		timeout = t.C
	}
	for {
		select {
		case f := <-c.in:
			if len(f.data) > b.Tailroom() {
				continue // 超缓冲丢弃(保包边界)
			}
			copy(b.ExtendTail(len(f.data)), f.data)
			return f.addr, nil
		case <-c.closed:
			if c.rerr != nil && c.rerr != io.EOF {
				return addr.Socksaddr{}, c.rerr
			}
			return addr.Socksaddr{}, net.ErrClosed
		case <-timeout:
			return addr.Socksaddr{}, os.ErrDeadlineExceeded
		}
	}
}

// WritePacket 客户端写「目的 = a」帧,服务端写「源 = a」帧。
func (c *frameConn) WritePacket(b *buf.Buffer, a addr.Socksaddr) error {
	ipa, err := c.ips.Resolve(a)
	if err != nil {
		if c.client {
			return err
		}
		ipa = addr.FromIPPort(netip.AddrPortFrom(netip.IPv4Unspecified(), a.Port)) // 回包来源解析不出:标 0.0.0.0,不丢包
	}
	a = ipa
	payload := b.Bytes()
	ip := encodeIP16(a.Addr)
	var frame []byte
	if c.client {
		frame = make([]byte, 0, 4+addrBlock+1+len(appName)+len(payload))
		frame = binary.BigEndian.AppendUint32(frame, uint32(addrBlock+1+len(appName)+len(payload)))
		frame = append(frame, make([]byte, 18)...) // 源 + 源端口 = 0
		frame = append(frame, ip[:]...)
		frame = binary.BigEndian.AppendUint16(frame, a.Port)
		frame = append(frame, byte(len(appName)))
		frame = append(frame, appName...)
	} else {
		frame = make([]byte, 0, 4+addrBlock+len(payload))
		frame = binary.BigEndian.AppendUint32(frame, uint32(addrBlock+len(payload)))
		frame = append(frame, ip[:]...)
		frame = binary.BigEndian.AppendUint16(frame, a.Port)
		frame = append(frame, make([]byte, 18)...) // 目的 + 目的端口 = 0
	}
	frame = append(frame, payload...)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.s.Write(frame)
	return err
}

func (c *frameConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		_ = c.s.Close()
	})
	return nil
}

func (c *frameConn) LocalAddr() net.Addr  { return ttAddr{} }
func (c *frameConn) RemoteAddr() net.Addr { return c.remote }
func (c *frameConn) SetDeadline(t time.Time) error {
	c.dmu.Lock()
	c.deadline = t
	c.dmu.Unlock()
	return nil
}
func (c *frameConn) Unwrap() any { return nil }
