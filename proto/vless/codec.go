// Package vless 实现 VLESS 协议(承设计第 3 章 §3.5.1,BandProxy)。
//
// 线格式对齐 Xray-core proxy/vless/encoding(逐字节复核):
//
//	请求头: version(1)=0 | UUID(16) | addonLen(1) + addons | command(1) |
//	         [TCP/UDP: port(2 BE) + atyp(1) + addr]   (PortThenAddress)
//	响应头: version(1)=0 | addonLen(1)=0
//
// VLESS 无自持 AEAD —— 加密靠下层传输(TLS/REALITY)。codec 纯函数,只碰 *buf.Buffer。
package vless

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
)

// Version 是 VLESS 协议版本(恒 0)。
const Version = byte(0x00)

// 命令字节(对齐 Xray RequestCommand)。
const (
	CmdTCP byte = 0x01
	CmdUDP byte = 0x02
	CmdMux byte = 0x03 // Mux.cool 载体:线上仅命令字节、不带地址(目标恒为 v1.mux.cool)
)

// 地址类型(对齐 Xray AddressType)。
const (
	atypIPv4   byte = 0x01
	atypDomain byte = 0x02
	atypIPv6   byte = 0x03
)

var (
	ErrShort   = errors.New("vless: short header")
	ErrVersion = errors.New("vless: bad version")
	ErrAtyp    = errors.New("vless: bad address type")
)

// RequestHeader 是 VLESS 请求头的解码结构。Addons 为原始 addon 字节(无 flow 时为空)。
type RequestHeader struct {
	UUID    [16]byte
	Addons  []byte
	Command byte
	Dst     addr.Socksaddr
}

// RequestCodec 是 VLESS 请求头的纯函数 codec。
type RequestCodec struct{}

// Encode 把请求头写进 dst 载荷区。
func (RequestCodec) Encode(dst *buf.Buffer, h RequestHeader) error {
	if err := dst.WriteByte(Version); err != nil {
		return err
	}
	if _, err := dst.Write(h.UUID[:]); err != nil {
		return err
	}
	if err := dst.WriteByte(byte(len(h.Addons))); err != nil {
		return err
	}
	if len(h.Addons) > 0 {
		if _, err := dst.Write(h.Addons); err != nil {
			return err
		}
	}
	if err := dst.WriteByte(h.Command); err != nil {
		return err
	}
	if h.Command == CmdTCP || h.Command == CmdUDP {
		if err := writeAddrPort(dst, h.Dst); err != nil {
			return err
		}
	}
	return nil
}

// Decode 从 src 解一个请求头,并 Advance 掉已消费字节(src 剩余即 payload)。
func (RequestCodec) Decode(src *buf.Buffer) (RequestHeader, error) {
	r := &reader{b: src.Bytes()}
	var h RequestHeader

	v, err := r.u8()
	if err != nil {
		return h, err
	}
	if v != Version {
		return h, ErrVersion
	}
	if err := r.read(h.UUID[:]); err != nil {
		return h, err
	}
	alen, err := r.u8()
	if err != nil {
		return h, err
	}
	if alen > 0 {
		h.Addons = make([]byte, alen)
		if err := r.read(h.Addons); err != nil {
			return h, err
		}
	}
	if h.Command, err = r.u8(); err != nil {
		return h, err
	}
	if h.Command == CmdTCP || h.Command == CmdUDP {
		if h.Dst, err = readAddrPort(r); err != nil {
			return h, err
		}
	}
	src.Advance(r.i)
	return h, nil
}

// EncodeResponseHeader 写响应头(version + addonLen 0)。
func EncodeResponseHeader(dst *buf.Buffer) error {
	if err := dst.WriteByte(Version); err != nil {
		return err
	}
	return dst.WriteByte(0)
}

func writeAddrPort(b *buf.Buffer, d addr.Socksaddr) error {
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], d.Port)
	if _, err := b.Write(pb[:]); err != nil {
		return err
	}
	switch {
	case d.IsFqdn():
		if err := b.WriteByte(atypDomain); err != nil {
			return err
		}
		if err := b.WriteByte(byte(len(d.Fqdn))); err != nil {
			return err
		}
		_, err := b.Write([]byte(d.Fqdn))
		return err
	case d.Addr.Is4():
		if err := b.WriteByte(atypIPv4); err != nil {
			return err
		}
		a := d.Addr.As4()
		_, err := b.Write(a[:])
		return err
	default:
		if err := b.WriteByte(atypIPv6); err != nil {
			return err
		}
		a := d.Addr.As16()
		_, err := b.Write(a[:])
		return err
	}
}

func readAddrPort(r *reader) (addr.Socksaddr, error) {
	var d addr.Socksaddr
	port, err := r.u16()
	if err != nil {
		return d, err
	}
	atyp, err := r.u8()
	if err != nil {
		return d, err
	}
	switch atyp {
	case atypIPv4:
		var a4 [4]byte
		if err := r.read(a4[:]); err != nil {
			return d, err
		}
		return addr.FromIPPort(netip.AddrPortFrom(netip.AddrFrom4(a4), port)), nil
	case atypDomain:
		l, err := r.u8()
		if err != nil {
			return d, err
		}
		name := make([]byte, l)
		if err := r.read(name); err != nil {
			return d, err
		}
		return addr.FromFqdn(string(name), port), nil
	case atypIPv6:
		var a16 [16]byte
		if err := r.read(a16[:]); err != nil {
			return d, err
		}
		return addr.FromIPPort(netip.AddrPortFrom(netip.AddrFrom16(a16), port)), nil
	default:
		return d, ErrAtyp
	}
}

// reader 是只读字节游标,越界返回 ErrShort。
type reader struct {
	b []byte
	i int
}

func (r *reader) u8() (byte, error) {
	if r.i+1 > len(r.b) {
		return 0, ErrShort
	}
	v := r.b[r.i]
	r.i++
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if r.i+2 > len(r.b) {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint16(r.b[r.i:])
	r.i += 2
	return v, nil
}

func (r *reader) read(p []byte) error {
	if r.i+len(p) > len(r.b) {
		return ErrShort
	}
	copy(p, r.b[r.i:])
	r.i += len(p)
	return nil
}
