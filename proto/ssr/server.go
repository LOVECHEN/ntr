package ssr

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/internal/ssr/shadowstream"
	sscore "github.com/LOVECHEN/ntr/internal/ssr/sscore"
)

var _ proxy.Server = (*Proxy)(nil)

// ServerHandshake 跑 SSR 服务端三层栈的逆向:obfs 服务端(解客户端首包伪装)→ cipher(对称,读客户端
// IV 解密)→ protocol 服务端(解客户端 auth 头 + chunk)→ 读 SOCKS5 目标地址,返回承载流 + Request。
//
// 服务端插件覆盖(逐步扩,禁改线格式):obfs=plain、protocol=origin 已通(透传 + 对称 cipher);
// auth_*/http_simple 等服务端逆向见 server_plugins.go。凭据走 password(Ambient,同 shadowsocks)。
func (p *Proxy) ServerHandshake(_ context.Context, below link.Stream, _ proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	cipher := p.cfg.Cipher
	if cipher == "" || cipher == "none" {
		cipher = "dummy"
	}
	coreCiph, err := sscore.PickCipher(cipher, nil, p.cfg.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("ssr: cipher:%w", err)
	}
	var (
		ivSize int
		key    []byte
	)
	if cipher == "dummy" {
		key = sscore.Kdf(p.cfg.Password, 16)
	} else {
		sc, ok := coreCiph.(*sscore.StreamCipher)
		if !ok {
			return nil, nil, fmt.Errorf("ssr: %q 非受支持的 stream cipher", p.cfg.Cipher)
		}
		ivSize = sc.IVSize()
		key = sc.Key
	}

	host, port := serverHostPort(below)

	// 服务端 obfs(解客户端首包伪装、之后裸流)。
	obConn, obOverhead, err := serverObfsConn(p.cfg.Obfs, below, key, ivSize, host, port, p.cfg.ObfsParam)
	if err != nil {
		return nil, nil, err
	}

	// cipher 对称:读客户端 IV 建解密器。
	cipherConn := coreCiph.StreamConn(obConn)
	var iv []byte
	if ss, ok := cipherConn.(*shadowstream.Conn); ok {
		if iv, err = ss.ObtainReadIV(); err != nil {
			return nil, nil, fmt.Errorf("ssr: 读客户端 IV:%w", err)
		}
	}

	// 服务端 protocol(解 auth 头 + chunk;回程 packData)。
	protoConn, err := serverProtocolConn(p.cfg.Protocol, cipherConn, iv, key, obOverhead, p.cfg.ProtocolParam)
	if err != nil {
		return nil, nil, err
	}

	dst, err := readSSRAddr(protoConn)
	if err != nil {
		return nil, nil, fmt.Errorf("ssr: 读目标地址:%w", err)
	}

	req := &proxy.Request{Cred: cred.Ref{ID: cred.Ambient}, Network: endpoint.NetworkTCP, Dst: dst}
	return &streamWrap{Conn: protoConn, below: below}, req, nil
}

// readSSRAddr 从解密流读 SOCKS5 目标地址头([ATYP][addr][port_be]),与客户端 serializeSSRAddr 对应。
func readSSRAddr(r io.Reader) (addr.Socksaddr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return addr.Socksaddr{}, err
	}
	var d addr.Socksaddr
	switch atyp[0] {
	case 0x01:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return d, err
		}
		d.Addr = netip.AddrFrom4(a)
	case 0x04:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return d, err
		}
		d.Addr = netip.AddrFrom16(a)
	case 0x03:
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
		return d, fmt.Errorf("ssr: 未知 ATYP %d", atyp[0])
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return d, err
	}
	d.Port = binary.BigEndian.Uint16(pb[:])
	return d, nil
}

// serverObfsConn 建服务端 obfs 包装。plain 透传;其余见 server_plugins.go。
func serverObfsConn(name string, below net.Conn, key []byte, ivSize int, host string, port int, param string) (net.Conn, int, error) {
	switch name {
	case "", "plain":
		return below, 0, nil
	default:
		return serverObfsPlugin(name, below, key, ivSize, host, port, param)
	}
}

// serverProtocolConn 建服务端 protocol 包装。origin 透传;其余见 server_plugins.go。
func serverProtocolConn(name string, c net.Conn, iv, key []byte, overhead int, param string) (net.Conn, error) {
	switch name {
	case "", "origin":
		return c, nil
	default:
		return serverProtocolPlugin(name, c, iv, key, overhead, param)
	}
}
