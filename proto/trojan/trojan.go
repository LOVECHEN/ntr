// Package trojan 实现 Trojan 协议(承设计第 3 章,BandProxy)。
//
// Trojan 是"TLS + 薄鉴权头":自身无 AEAD,机密性与抗探测全靠下层 TLS。它天然叠在
// transport/tls 之上 —— 正是分层栈的示范:trojan 只写/读一个头,加解密/伪装一字不碰。
//
// 线格式(客户端→服务端):
//
//	hex(SHA224(password))(56) | CRLF | CMD(1) ATYP(1) ADDR PORT(2) | CRLF | payload...
//
// 多用户:每个口一份 TLS;用户身份 = 头部 56 字节 hash,经 Authenticator 解析到 CredID。
// 鉴权失败真 trojan 会回落到伪装网站(fallback)—— 本层只响亮报错,回落由【service 层协议无关地实现】:
// 入站配 fallback=真站后,任何协议(trojan/vless/…)握手失败都把连接原样中继到该站(见 service/inbound.go
// 的 recordStream/doFallback;禁改本协议线格式)。对 xray 行为验过(ix-fallback.sh)。
package trojan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

var (
	_ proxy.Server          = (*Proxy)(nil)
	_ proxy.Client          = (*Proxy)(nil)
	_ proxy.CredentialCodec = (*Proxy)(nil)
)

const hashLen = 56 // hex(SHA224) = 28 字节 → 56 hex 字符

// 命令 / 地址类型(SOCKS5 寻址:地址在前、端口在后)。
const (
	CmdConnect byte = 0x01
	CmdUDP     byte = 0x03

	atypIPv4   byte = 0x01
	atypDomain byte = 0x03
	atypIPv6   byte = 0x04
)

var (
	ErrBadHeader = errors.New("trojan: 头部格式错(CRLF 缺失)")
	ErrAtyp      = errors.New("trojan: 未知地址类型")
	ErrAuth      = errors.New("trojan: 鉴权失败(未知 password hash)")
)

// Key 由 password 派生线上鉴权键 = hex(SHA224(password))。服务端用它登记用户,
// 客户端握手时现算 —— 两侧同源,不必传明文口令。
func Key(password string) []byte {
	sum := sha256.Sum224([]byte(password))
	dst := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(dst, sum[:])
	return dst
}

// Config 是 Trojan 自有配置(鉴权在外部 Authenticator,故当前为空;fallback 后续加)。
type Config struct{}

// Proxy 是 Trojan 连接级句柄。
type Proxy struct{ cfg Config }

// Build 构造 Proxy。
func Build(_ context.Context, cfg Config, _ any) (any, error) { return &Proxy{cfg: cfg}, nil }

// ClientKey / AuthKey 实现 proxy.CredentialCodec:Trojan 的两侧【不同】——
// 客户端出示明文口令(ClientHandshake 内部现算 hash),服务端登记 hex(SHA224(口令))。
func (*Proxy) ClientKey(secret string) ([]byte, error) { return []byte(secret), nil }
func (*Proxy) AuthKey(secret string) ([]byte, error)   { return Key(secret), nil }

// ServerHandshake 实现 proxy.Server:读头 → 校验 CRLF → 解 dst → 按 hash 鉴权 →
// 返回下层 stream(其上余字节即 payload,直接中继)。
func (p *Proxy) ServerHandshake(_ context.Context, below link.Stream, auth proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	h := make([]byte, hashLen)
	if _, err := io.ReadFull(below, h); err != nil {
		return nil, nil, err
	}
	if err := expectCRLF(below); err != nil {
		return nil, nil, err
	}
	cmd, dst, err := readRequest(below)
	if err != nil {
		return nil, nil, err
	}
	if err := expectCRLF(below); err != nil {
		return nil, nil, err
	}
	ref, ok := auth.Auth("trojan", h)
	if !ok {
		return nil, nil, ErrAuth
	}
	net := endpoint.NetworkTCP
	if cmd == CmdUDP {
		net = endpoint.NetworkUDP
	}
	return below, &proxy.Request{Cred: ref, Network: net, Command: cmd, Dst: dst}, nil
}

// ClientHandshake 实现 proxy.Client:key=password,现算 hash,写头,之后 payload 直接过下层。
func (p *Proxy) ClientHandshake(_ context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.Stream, error) {
	var b bytes.Buffer
	b.Write(Key(string(key)))
	b.WriteString("\r\n")
	writeRequest(&b, CmdConnect, dst)
	b.WriteString("\r\n")
	if _, err := below.Write(b.Bytes()); err != nil {
		return nil, err
	}
	return below, nil
}

func expectCRLF(r io.Reader) error {
	var c [2]byte
	if _, err := io.ReadFull(r, c[:]); err != nil {
		return err
	}
	if c[0] != '\r' || c[1] != '\n' {
		return ErrBadHeader
	}
	return nil
}

func readRequest(r io.Reader) (byte, addr.Socksaddr, error) {
	var head [2]byte // CMD, ATYP
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, addr.Socksaddr{}, err
	}
	cmd, atyp := head[0], head[1]

	var host addr.Socksaddr
	switch atyp {
	case atypIPv4:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return 0, host, err
		}
		host.Addr = netip.AddrFrom4(a)
	case atypIPv6:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return 0, host, err
		}
		host.Addr = netip.AddrFrom16(a)
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return 0, host, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return 0, host, err
		}
		host.Fqdn = string(name)
	default:
		return 0, host, ErrAtyp
	}

	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return 0, host, err
	}
	host.Port = binary.BigEndian.Uint16(pb[:])
	return cmd, host, nil
}

func writeRequest(w *bytes.Buffer, cmd byte, d addr.Socksaddr) {
	w.WriteByte(cmd)
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
