// Package socks 实现 SOCKS4/4a/5(承设计第 3 章,BandProxy),入站与出站两向皆备:
//   - 入站(proxy.Server):收 SOCKS 流量解出目标交出站 —— 常作本地入站,收本机应用流量。
//   - 出站(proxy.Client + PacketConnClient,见 client.go):把逻辑目标交给上游 SOCKS5 服务器
//     (CONNECT / UDP ASSOCIATE)—— 链式部署里 NTR 作 socks 客户端转发到上游 socks 代理。
//
// 它只是 proxy 插件,和 vless/trojan 平级 —— 本地入站 vs 远端协议入站在核心眼里无差别,
// 同一条 HandleStream 路径;出站同理复用 upstream。
//
// 注:SOCKS5 需在连上目标"之后"回 reply,而统一契约无 post-dial 回调,故服务端握手里乐观回
// success(标准做法);出站真失败则连接随即关闭。UDP:入站 ASSOCIATE 见 udp.go,出站见 client.go。
package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"slices"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

var (
	_ proxy.Server          = (*Proxy)(nil)
	_ proxy.CredentialCodec = (*Proxy)(nil) // per-user 凭据 "user:pass"(RFC 1929),两端 identity
	_ proxy.AuthGate        = (*Proxy)(nil) // 本口配了 users → 必须 user/pass 子协商,未匹配即拒
)

const version = 0x05

// 命令 / 地址类型(SOCKS5)。
const (
	CmdConnect   byte = 0x01
	CmdUDPAssoc  byte = 0x03
	atypIPv4     byte = 0x01
	atypDomain   byte = 0x03
	atypIPv6     byte = 0x04
	methodNoAuth byte = 0x00
	methodNone   byte = 0xFF
)

var (
	ErrVersion     = errors.New("socks: 非 SOCKS5")
	ErrNoAuth      = errors.New("socks: 客户端未提供可接受的认证方法")
	ErrAuthVersion = errors.New("socks: RFC1929 子协商版本非 1")
	ErrAuthFailed  = errors.New("socks: user/pass 未匹配任何凭据")
	ErrAtyp        = errors.New("socks: 未知地址类型")
	ErrCommand     = errors.New("socks: 仅支持 CONNECT")
)

// Config 是 SOCKS 自有配置(无线上参数;鉴权由顶层 users 经 Authenticator 提供)。
type Config struct{}

// Proxy 是连接级句柄(Descriptor.Build 产物,连接间复用;authRequired 装配期一次性设定)。
type Proxy struct {
	cfg          Config
	authRequired bool // 装配侧经 AuthGate 告知:本口配了 per-user 凭据 → 必须 RFC1929,未匹配即拒
}

// Build 构造 Proxy。
func Build(_ context.Context, cfg Config, _ any) (any, error) { return &Proxy{cfg: cfg}, nil }

// ClientKey / AuthKey:凭据串 "user:pass" 原样(与 client.go 的 RFC1929 子协商同一约定);
// SetAuthRequired 由装配侧调用。
func (*Proxy) ClientKey(secret string) ([]byte, error) { return []byte(secret), nil }
func (*Proxy) AuthKey(secret string) ([]byte, error)   { return []byte(secret), nil }
func (p *Proxy) SetAuthRequired(required bool)         { p.authRequired = required }

// serverUserPass 服务端 RFC 1929 子协商:读 [VER ULEN USER PLEN PASS],以 (socks, "user:pass")
// 精确匹配顶层 users;未命中回状态 0x01 并拒。
func serverUserPass(below link.Stream, auth proxy.Authenticator) (cred.Ref, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(below, hdr[:]); err != nil {
		return cred.Ref{}, err
	}
	if hdr[0] != authVersion {
		return cred.Ref{}, ErrAuthVersion
	}
	user := make([]byte, hdr[1])
	if _, err := io.ReadFull(below, user); err != nil {
		return cred.Ref{}, err
	}
	var pl [1]byte
	if _, err := io.ReadFull(below, pl[:]); err != nil {
		return cred.Ref{}, err
	}
	pass := make([]byte, pl[0])
	if _, err := io.ReadFull(below, pass); err != nil {
		return cred.Ref{}, err
	}
	key := make([]byte, 0, len(user)+1+len(pass))
	key = append(append(append(key, user...), ':'), pass...)
	r, ok := auth.Auth("socks", key)
	if !ok {
		_, _ = below.Write([]byte{authVersion, 0x01})
		return cred.Ref{}, ErrAuthFailed
	}
	if _, err := below.Write([]byte{authVersion, 0x00}); err != nil {
		return cred.Ref{}, err
	}
	return r, nil
}

// ServerHandshake 实现 proxy.Server:方法协商(no-auth)→ 读请求 → 乐观回 success →
// 返回下层 stream(其上即 payload)。
func (p *Proxy) ServerHandshake(_ context.Context, below link.Stream, auth proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	// 先读版本字节,按版本分派(SOCKS5 与 SOCKS4/4a 线格式完全不同)。
	var v [1]byte
	if _, err := io.ReadFull(below, v[:]); err != nil {
		return nil, nil, err
	}
	switch v[0] {
	case version:
		return p.serverHandshake5(below, auth)
	case version4:
		return p.serverHandshake4(below, auth)
	default:
		return nil, nil, ErrVersion
	}
}

// serverHandshake5 是 SOCKS5 握手(VER 字节已被调用方消费)。
func (p *Proxy) serverHandshake5(below link.Stream, auth proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	// 问候剩余:NMETHODS METHODS...
	var nm [1]byte
	if _, err := io.ReadFull(below, nm[:]); err != nil {
		return nil, nil, err
	}
	methods := make([]byte, nm[0])
	if _, err := io.ReadFull(below, methods); err != nil {
		return nil, nil, err
	}
	// 方法协商:本口配了 users → 只接受 RFC1929(0x02),子协商命中即得该用户;
	// 没配 → 保持 no-auth(本地入站语义不变)。
	ref := cred.Ref{ID: cred.Ambient}
	switch {
	case p.authRequired:
		if !slices.Contains(methods, methodUserPass) {
			_, _ = below.Write([]byte{version, methodNone})
			return nil, nil, ErrNoAuth
		}
		if _, err := below.Write([]byte{version, methodUserPass}); err != nil {
			return nil, nil, err
		}
		r, err := serverUserPass(below, auth)
		if err != nil {
			return nil, nil, err
		}
		ref = r
	case slices.Contains(methods, methodNoAuth):
		if _, err := below.Write([]byte{version, methodNoAuth}); err != nil {
			return nil, nil, err
		}
	default:
		_, _ = below.Write([]byte{version, methodNone})
		return nil, nil, ErrNoAuth
	}

	// 请求:VER CMD RSV ATYP ADDR PORT
	var h [4]byte
	if _, err := io.ReadFull(below, h[:]); err != nil {
		return nil, nil, err
	}
	if h[0] != version {
		return nil, nil, ErrVersion
	}
	cmd := h[1]
	dst, err := readAddr(below, h[3])
	if err != nil {
		return nil, nil, err
	}

	if cmd == CmdUDPAssoc {
		return p.handleUDPAssoc(below)
	}
	if cmd != CmdConnect { // BIND 待办:回 command-not-supported
		_, _ = below.Write(reply(0x07))
		return nil, nil, ErrCommand
	}
	if _, err := below.Write(reply(0x00)); err != nil { // 乐观 success
		return nil, nil, err
	}

	// ref:no-auth 口为 Ambient(可由 by-inbound 覆盖);配了 users 则是子协商命中的用户。
	// 注:UDP ASSOCIATE 走 handleUDPAssoc 自建 Request,其 Cred 归属尚未透传 ref(per-user UDP 计量后续)。
	return below, &proxy.Request{Cred: ref, Network: endpoint.NetworkTCP, Command: cmd, Dst: dst}, nil
}

// reply 构造 SOCKS5 应答(BND.ADDR=0.0.0.0:0)。
func reply(rep byte) []byte {
	return []byte{version, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
}

func readAddr(r io.Reader, atyp byte) (addr.Socksaddr, error) {
	var d addr.Socksaddr
	switch atyp {
	case atypIPv4:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return d, err
		}
		d.Addr = netip.AddrFrom4(a)
	case atypIPv6:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return d, err
		}
		d.Addr = netip.AddrFrom16(a)
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return d, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return d, err
		}
		d.Fqdn = string(name)
	default:
		return d, ErrAtyp
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return d, err
	}
	d.Port = binary.BigEndian.Uint16(pb[:])
	return d, nil
}
