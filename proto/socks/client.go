package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// SOCKS 也作【出站】:proxy.Client(CONNECT)+ PacketConnClient(UDP ASSOCIATE),把逻辑目标
// 交给上游 SOCKS5 服务器。线格式与服务端同源(RFC 1928/1929),只是方向相反 —— 不新增/不改任何字节。
var (
	_ proxy.Client           = (*Proxy)(nil)
	_ proxy.PacketConnClient = (*Proxy)(nil)
)

const (
	methodUserPass byte = 0x02 // RFC 1929 用户名/口令
	authVersion    byte = 0x01 // RFC 1929 子协商版本
)

// ClientHandshake 实现 proxy.Client:方法协商(no-auth,key 非空则也提供 user/pass)→
// CONNECT 请求 → 读应答 → 返回下层 stream(其上即 payload)。key 语义 "user:pass"(可空)。
func (p *Proxy) ClientHandshake(_ context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.Stream, error) {
	if err := p.clientNegotiate(below, key); err != nil {
		return nil, err
	}
	// 请求:VER CMD RSV ATYP ADDR PORT
	req := []byte{version, CmdConnect, 0x00}
	req = append(req, writeSocksAddr(dst)...)
	if _, err := below.Write(req); err != nil {
		return nil, err
	}
	if _, _, err := readReply(below); err != nil {
		return nil, err
	}
	return below, nil
}

// clientNegotiate 跑方法协商(+ 需要则 RFC1929 user/pass 子协商)。
func (p *Proxy) clientNegotiate(below link.Stream, key []byte) error {
	methods := []byte{methodNoAuth}
	if len(key) > 0 {
		methods = append(methods, methodUserPass)
	}
	greet := []byte{version, byte(len(methods))}
	greet = append(greet, methods...)
	if _, err := below.Write(greet); err != nil {
		return err
	}
	var sel [2]byte
	if _, err := io.ReadFull(below, sel[:]); err != nil {
		return err
	}
	if sel[0] != version {
		return ErrVersion
	}
	switch sel[1] {
	case methodNoAuth:
		return nil
	case methodUserPass:
		return clientUserPass(below, key)
	case methodNone:
		return errors.New("socks: 上游拒绝所有认证方法")
	default:
		return fmt.Errorf("socks: 上游选了不支持的认证方法 %#x", sel[1])
	}
}

// clientUserPass 跑 RFC 1929 子协商。key = "user:pass"(缺冒号则整体作用户名、口令空)。
func clientUserPass(below link.Stream, key []byte) error {
	user, pass := key, []byte(nil)
	for i, c := range key {
		if c == ':' {
			user, pass = key[:i], key[i+1:]
			break
		}
	}
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("socks: user/pass 超 255 字节")
	}
	msg := []byte{authVersion, byte(len(user))}
	msg = append(msg, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)
	if _, err := below.Write(msg); err != nil {
		return err
	}
	var st [2]byte
	if _, err := io.ReadFull(below, st[:]); err != nil {
		return err
	}
	if st[1] != 0x00 { // RFC 1929:0 = 成功
		return errors.New("socks: user/pass 认证失败")
	}
	return nil
}

// DialPacketConn 实现 proxy.PacketConnClient:UDP ASSOCIATE。在 below(TCP 控制连接)上协商 +
// 发 UDP ASSOCIATE 请求(请求地址 0.0.0.0:0 = 让服务器接受任意源),取回中继 BND.ADDR:PORT,
// 另建 UDP socket 连到中继,包成 link.PacketConn(收发加/剥 SOCKS-UDP 头)。控制连接存活维系关联。
func (p *Proxy) DialPacketConn(_ context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.PacketConn, error) {
	if err := p.clientNegotiate(below, key); err != nil {
		return nil, err
	}
	// UDP ASSOCIATE 请求地址填全零(客户端不预先绑定源)。
	req := []byte{version, CmdUDPAssoc, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := below.Write(req); err != nil {
		return nil, err
	}
	relay, _, err := readReply(below)
	if err != nil {
		return nil, err
	}
	// BND.ADDR 若为全零(服务器让客户端用它连 TCP 时的对端 IP),回落到 below 的远端 IP。
	relayAddr := relay
	if relay.Addr.IsValid() && relay.Addr.IsUnspecified() || !relay.Addr.IsValid() {
		if ra, ok := below.RemoteAddr().(*net.TCPAddr); ok {
			relayAddr = addr.FromIPPort(ra.AddrPort())
			relayAddr.Port = relay.Port
		}
	}
	uconn, err := net.Dial("udp", relayAddr.String())
	if err != nil {
		return nil, err
	}
	return &clientUDPConn{conn: uconn.(*net.UDPConn), below: below, dst: dst}, nil
}

// clientUDPConn 把中继 UDP socket 抬成单目标 link.PacketConn:发时前置 SOCKS-UDP 头(目标=dst),
// 收时剥头。控制 TCP 连接随本 conn 生命周期存活(Close 一并关),维系 UDP ASSOCIATE 关联。
type clientUDPConn struct {
	conn  *net.UDPConn
	below link.Stream
	dst   addr.Socksaddr
	once  sync.Once
}

var _ link.PacketConn = (*clientUDPConn)(nil)

// ReadPacket 读一个中继回来的 UDP 包,剥 [RSV(2)][FRAG][ATYP][ADDR][PORT] 头,b 留 payload。
func (c *clientUDPConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	for {
		b.Reset()
		n, err := c.conn.Read(b.ExtendTail(b.Tailroom()))
		if err != nil {
			return addr.Socksaddr{}, err
		}
		b.Truncate(n)
		p := b.Bytes()
		if len(p) < 4 || p[2] != 0 { // 过短 / 分片 → 丢弃继续
			continue
		}
		src, hdrLen, err := parseUDPAddr(p[3:])
		if err != nil {
			continue
		}
		b.Advance(3 + hdrLen)
		return src, nil
	}
}

// WritePacket 前置 SOCKS-UDP 头(目标=dst)后发往中继。
func (c *clientUDPConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	hdr := encodeUDPHeader(dst)
	copy(b.ExtendHeader(len(hdr)), hdr)
	_, err := c.conn.Write(b.Bytes())
	return err
}

func (c *clientUDPConn) Close() error {
	c.once.Do(func() {
		_ = c.conn.Close()
		_ = c.below.Close() // 关控制连接 → 上游收尾 UDP 关联
	})
	return nil
}
func (c *clientUDPConn) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *clientUDPConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *clientUDPConn) Unwrap() any                   { return c.conn }

// readReply 读 SOCKS5 应答 VER REP RSV ATYP ADDR PORT,REP!=0 报错,返回 BND 地址。
func readReply(r io.Reader) (addr.Socksaddr, byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return addr.Socksaddr{}, 0, err
	}
	if h[0] != version {
		return addr.Socksaddr{}, 0, ErrVersion
	}
	if h[1] != 0x00 {
		return addr.Socksaddr{}, h[1], fmt.Errorf("socks: 上游拒绝,REP=%#x", h[1])
	}
	bnd, err := readAddr(r, h[3])
	return bnd, 0x00, err
}

// writeSocksAddr 编码 [ATYP][ADDR][PORT](CONNECT/请求用,无 RSV/FRAG)。
func writeSocksAddr(dst addr.Socksaddr) []byte {
	var out []byte
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
