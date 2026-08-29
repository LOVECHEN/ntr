package vless

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// VLESS 作为纯插件也实现 UDP-over-stream 的可选能力(单目标 datagram)。
var (
	_ proxy.PacketConnServer = (*Proxy)(nil)
	_ proxy.PacketConnClient = (*Proxy)(nil)
)

var errPacketTooLarge = errors.New("vless: UDP 包超 64KiB 或超出缓冲")

// DialPacketConn 实现 proxy.PacketConnClient:写 VLESS UDP 请求头(Command=UDP),返回
// 单目标 PacketConn(响应头由内部 clientStream 首读透明 strip)。
func (p *Proxy) DialPacketConn(_ context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.PacketConn, error) {
	if p.cfg.Flow != "" {
		return nil, fmt.Errorf("vless: flow %q not yet implemented", p.cfg.Flow)
	}
	if len(key) != 16 {
		return nil, fmt.Errorf("vless: uuid key must be 16 bytes, got %d", len(key))
	}
	var uuid [16]byte
	copy(uuid[:], key)
	if err := writeRequestHeader(below, uuid, CmdUDP, dst); err != nil {
		return nil, err
	}
	return &packetConn{stream: &clientStream{Stream: below}, dst: dst}, nil
}

// ServerPacketConn 实现 proxy.PacketConnServer:把 UDP 请求握手后的 stream(ServerHandshake
// 返回的 serverStream,首写透明前置响应头)适配成单目标 PacketConn。
func (p *Proxy) ServerPacketConn(below link.Stream, dst addr.Socksaddr) (link.PacketConn, error) {
	return &packetConn{stream: below, dst: dst}, nil
}

// packetConn 用 [len(2 BE)][payload] 分帧在 stream 上承载单目标 UDP datagram(VLESS UDP over TCP)。
type packetConn struct {
	stream link.Stream
	dst    addr.Socksaddr
}

var _ link.PacketConn = (*packetConn)(nil)

// ReadPacket 读一个 datagram 到 b(dst 恒为握手目标,单目标语义)。
func (c *packetConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.stream, hdr[:]); err != nil {
		return addr.Socksaddr{}, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > b.Tailroom() {
		return addr.Socksaddr{}, errPacketTooLarge
	}
	if _, err := io.ReadFull(c.stream, b.ExtendTail(n)); err != nil {
		return addr.Socksaddr{}, err
	}
	return c.dst, nil
}

// WritePacket 把 b 作为一个 datagram 分帧写入 stream(前置 2 字节长度)。
func (c *packetConn) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error {
	n := b.Len()
	if n > 0xFFFF {
		return errPacketTooLarge
	}
	binary.BigEndian.PutUint16(b.ExtendHeader(2), uint16(n))
	_, err := c.stream.Write(b.Bytes())
	return err
}

func (c *packetConn) Close() error                       { return c.stream.Close() }
func (c *packetConn) LocalAddr() net.Addr                { return c.stream.LocalAddr() }
func (c *packetConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *packetConn) Unwrap() any                        { return c.stream }
