package trojan

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// Trojan 也实现 UDP-over-stream 能力(多目标:每包自带地址,不同于 VLESS 的单目标)。
var (
	_ proxy.PacketConnServer = (*Proxy)(nil)
	_ proxy.PacketConnClient = (*Proxy)(nil)
)

var errUDPTooLarge = errors.New("trojan: UDP 包超 64KiB 或超出缓冲")

// DialPacketConn 实现 proxy.PacketConnClient:写 trojan UDP 请求头(Command=UDP,首目标=dst),
// 返回多目标 PacketConn。trojan UDP 每包格式 [ATYP][ADDR][PORT][LEN(2 BE)][CRLF][PAYLOAD]。
func (p *Proxy) DialPacketConn(_ context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.PacketConn, error) {
	var b bytes.Buffer
	b.Write(Key(string(key)))
	b.WriteString("\r\n")
	writeRequest(&b, CmdUDP, dst)
	b.WriteString("\r\n")
	if _, err := below.Write(b.Bytes()); err != nil {
		return nil, err
	}
	return &packetConn{stream: below}, nil
}

// ServerPacketConn 实现 proxy.PacketConnServer:把 UDP 握手后的 stream 适配成多目标 PacketConn。
func (p *Proxy) ServerPacketConn(below link.Stream, _ addr.Socksaddr) (link.PacketConn, error) {
	return &packetConn{stream: below}, nil
}

type packetConn struct {
	stream link.Stream
}

var _ link.PacketConn = (*packetConn)(nil)

// ReadPacket 读一个 trojan UDP 帧到 b,返回该包的目标地址(多目标)。
func (c *packetConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	dst, err := readSocksAddr(c.stream)
	if err != nil {
		return addr.Socksaddr{}, err
	}
	var lc [4]byte // length(2 BE) + CRLF(2)
	if _, err := io.ReadFull(c.stream, lc[:]); err != nil {
		return addr.Socksaddr{}, err
	}
	if lc[2] != 0x0D || lc[3] != 0x0A {
		return addr.Socksaddr{}, errors.New("trojan: UDP 帧缺 CRLF")
	}
	n := int(binary.BigEndian.Uint16(lc[:2]))
	if n > b.Tailroom() {
		return addr.Socksaddr{}, errUDPTooLarge
	}
	if _, err := io.ReadFull(c.stream, b.ExtendTail(n)); err != nil {
		return addr.Socksaddr{}, err
	}
	return dst, nil
}

// WritePacket 把 b 作为一个 trojan UDP 帧写入 stream(前置 [ATYP][ADDR][PORT][LEN][CRLF])。
func (c *packetConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	n := b.Len()
	if n > 0xFFFF {
		return errUDPTooLarge
	}
	var hdr bytes.Buffer
	writeSocksAddr(&hdr, dst)
	var lc [4]byte
	binary.BigEndian.PutUint16(lc[:2], uint16(n))
	lc[2], lc[3] = 0x0D, 0x0A
	hdr.Write(lc[:])
	hb := hdr.Bytes()
	copy(b.ExtendHeader(len(hb)), hb) // 一次成型:头前置到同一缓冲,单次写出
	_, err := c.stream.Write(b.Bytes())
	return err
}

func (c *packetConn) Close() error                  { return c.stream.Close() }
func (c *packetConn) LocalAddr() net.Addr           { return c.stream.LocalAddr() }
func (c *packetConn) SetDeadline(t time.Time) error { return c.stream.SetDeadline(t) }
func (c *packetConn) Unwrap() any                   { return c.stream }

// writeSocksAddr 写 SOCKS5 风格地址 [ATYP][ADDR][PORT](与 writeRequest 的地址部分同构,无 cmd)。
func writeSocksAddr(w *bytes.Buffer, d addr.Socksaddr) {
	switch {
	case d.IsFqdn():
		w.WriteByte(atypDomain)
		w.WriteByte(byte(len(d.Fqdn)))
		w.WriteString(d.Fqdn)
	case d.Addr.Is4():
		w.WriteByte(atypIPv4)
		a := d.Addr.As4()
		w.Write(a[:])
	default:
		w.WriteByte(atypIPv6)
		a := d.Addr.As16()
		w.Write(a[:])
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], d.Port)
	w.Write(pb[:])
}

// readSocksAddr 读 SOCKS5 风格地址(与 readRequest 的地址部分同构,无 cmd)。
func readSocksAddr(r io.Reader) (addr.Socksaddr, error) {
	var at [1]byte
	if _, err := io.ReadFull(r, at[:]); err != nil {
		return addr.Socksaddr{}, err
	}
	switch at[0] {
	case atypIPv4:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return addr.Socksaddr{}, err
		}
		return readPort(r, netip.AddrFrom4(a))
	case atypIPv6:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return addr.Socksaddr{}, err
		}
		return readPort(r, netip.AddrFrom16(a))
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return addr.Socksaddr{}, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return addr.Socksaddr{}, err
		}
		var pb [2]byte
		if _, err := io.ReadFull(r, pb[:]); err != nil {
			return addr.Socksaddr{}, err
		}
		return addr.FromFqdn(string(name), binary.BigEndian.Uint16(pb[:])), nil
	default:
		return addr.Socksaddr{}, ErrAtyp
	}
}

func readPort(r io.Reader, ip netip.Addr) (addr.Socksaddr, error) {
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return addr.Socksaddr{}, err
	}
	return addr.FromIPPort(netip.AddrPortFrom(ip, binary.BigEndian.Uint16(pb[:]))), nil
}
