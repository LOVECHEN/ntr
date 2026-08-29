// Package ssr 实现 ShadowsocksR(SSR)客户端 —— 经典的 SS 流加密 + protocol 插件 + obfs 插件三层栈。
//
// ★禁改线格式:底层的 obfs / protocol / stream-cipher 三套插件直接 vendored 自 mihomo
// (github.com/metacubex/mihomo/transport/ssr → ntr/internal/ssr,见该目录 doc),字节即 mihomo,
// 与任何标准 SSR 服务端(shadowsocksr-libev / mihomo 客户端所连之服务端)线级互通。
//
// 客户端握手栈(自外向内包裹,数据 Write 时 protocol→cipher→obfs→wire):
//  1. obfs.StreamConn(below)   —— 首包伪装(plain/http_simple/tls1.2_ticket_auth 等)
//  2. cipher.StreamConn(c)     —— SS 流加密(rc4-md5/aes-*-cfb/ctr/chacha20-ietf 等),首写落随机 IV
//  3. protocol.StreamConn(c,iv)—— 会话协议(origin/auth_aes128_sha1/auth_chain_a 等),用 IV 作密钥料
//  4. 写 SOCKS5 目标地址头,之后即裸载荷双向。
//
// 仅客户端(出站):xray/sing-box/mihomo 三家均无 SSR 入站监听,故 NTR 不设 SSR 服务端(与 mtproto
// 半向同理);SSR 服务端侧由参考实现验证 NTR 客户端。占 BandProxy,叠 [tcp, ssr] 或 [ssr]。
package ssr

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"

	"github.com/LOVECHEN/ntr/internal/ssr/obfs"
	"github.com/LOVECHEN/ntr/internal/ssr/protocol"
	"github.com/LOVECHEN/ntr/internal/ssr/shadowstream"
	sscore "github.com/LOVECHEN/ntr/internal/ssr/sscore"
	"github.com/LOVECHEN/ntr/core/spec"
)

var _ proxy.Client = (*Proxy)(nil)

// Config 是 SSR 配置。Cipher=SS 流加密名(aes-256-cfb/rc4-md5/chacha20-ietf/none…);
// Protocol/Obfs=SSR 两套插件名 + 各自 param。
type Config struct {
	Cipher        string
	Password      string
	Protocol      string
	ProtocolParam string
	Obfs          string
	ObfsParam     string
}

// Parse 从哑节点解出 Config。键名对齐 mihomo:cipher/password/protocol/protocol-param/obfs/obfs-param。
func Parse(n *spec.Node) (Config, error) {
	c := Config{
		Cipher:        n.Get("cipher").Str(),
		Password:      n.Get("password").Str(),
		Protocol:      n.Get("protocol").Str(),
		ProtocolParam: n.Get("protocol-param").Str(),
		Obfs:          n.Get("obfs").Str(),
		ObfsParam:     n.Get("obfs-param").Str(),
	}
	if c.Protocol == "" {
		c.Protocol = "origin"
	}
	if c.Obfs == "" {
		c.Obfs = "plain"
	}
	return c, nil
}

// Proxy 是 SSR 客户端句柄。obfs/protocol 有 per-连接状态,故在每次握手时新建,不共享。
type Proxy struct {
	cfg Config
}

// Build 校验 cipher 可用后构造 Proxy(obfs/protocol 延到握手时按连接新建)。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	cipher := cfg.Cipher
	if cipher == "" || cipher == "none" {
		cipher = "dummy"
	}
	if _, err := sscore.PickCipher(cipher, nil, cfg.Password); err != nil {
		return nil, fmt.Errorf("ssr: cipher %q:%w", cfg.Cipher, err)
	}
	// 校验 obfs/protocol 名合法(用占位 Base 试建,不留状态)。
	if _, _, err := obfs.PickObfs(cfg.Obfs, &obfs.Base{}); err != nil {
		return nil, fmt.Errorf("ssr: %w", err)
	}
	if _, err := protocol.PickProtocol(cfg.Protocol, &protocol.Base{}); err != nil {
		return nil, fmt.Errorf("ssr: %w", err)
	}
	return &Proxy{cfg: cfg}, nil
}

// ClientHandshake 跑 SSR 客户端三层栈并写目标地址头。key 参数不用(SSR 凭据是 password,在 Config)。
func (p *Proxy) ClientHandshake(_ context.Context, below link.Stream, _ []byte, dst addr.Socksaddr) (link.Stream, error) {
	cipher := p.cfg.Cipher
	if cipher == "" || cipher == "none" {
		cipher = "dummy"
	}
	coreCiph, err := sscore.PickCipher(cipher, nil, p.cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("ssr: cipher:%w", err)
	}

	var (
		ivSize int
		key    []byte
	)
	if cipher == "dummy" {
		ivSize = 0
		key = sscore.Kdf(p.cfg.Password, 16)
	} else {
		sc, ok := coreCiph.(*sscore.StreamCipher)
		if !ok {
			return nil, fmt.Errorf("ssr: %q 非受支持的 stream cipher", p.cfg.Cipher)
		}
		ivSize = sc.IVSize()
		key = sc.Key
	}

	// obfs 的 Host/Port 用服务端地址(below 已连上游);obfs-param 覆盖伪装主机时由 Base.Param 承接。
	host, port := serverHostPort(below)

	ob, obOverhead, err := obfs.PickObfs(p.cfg.Obfs, &obfs.Base{
		Host:   host,
		Port:   port,
		Key:    key,
		IVSize: ivSize,
		Param:  p.cfg.ObfsParam,
	})
	if err != nil {
		return nil, fmt.Errorf("ssr: obfs:%w", err)
	}
	pr, err := protocol.PickProtocol(p.cfg.Protocol, &protocol.Base{
		Key:      key,
		Overhead: obOverhead,
		Param:    p.cfg.ProtocolParam,
	})
	if err != nil {
		return nil, fmt.Errorf("ssr: protocol:%w", err)
	}

	// 三层包裹(与 mihomo adapter 一致):obfs → cipher → protocol(套 write-IV)。
	c := ob.StreamConn(below)
	c = coreCiph.StreamConn(c)
	var iv []byte
	if ss, ok := c.(*shadowstream.Conn); ok {
		if iv, err = ss.ObtainWriteIV(); err != nil {
			return nil, fmt.Errorf("ssr: 取 write-IV:%w", err)
		}
	}
	c = pr.StreamConn(c, iv)

	if _, err := c.Write(serializeSSRAddr(dst)); err != nil {
		return nil, fmt.Errorf("ssr: 写目标头:%w", err)
	}
	return &streamWrap{Conn: c, below: below}, nil
}

// serverHostPort 从 below 的对端地址取服务端 host/port(供 obfs 伪装用)。
func serverHostPort(below link.Stream) (string, int) {
	if ra := below.RemoteAddr(); ra != nil {
		if h, ps, err := net.SplitHostPort(ra.String()); err == nil {
			port, _ := strconv.Atoi(ps)
			return h, port
		}
	}
	return "", 0
}

// serializeSSRAddr 把目标序列化为 SOCKS5 地址头([ATYP][addr][port_be]),与 mihomo
// serializesSocksAddr 逐字节一致(domain 03/len、IPv4 01、IPv6 04)。
func serializeSSRAddr(dst addr.Socksaddr) []byte {
	var out []byte
	switch {
	case dst.IsFqdn():
		out = append(out, 0x03, byte(len(dst.Fqdn)))
		out = append(out, dst.Fqdn...)
	case dst.Addr.Is4():
		out = append(out, 0x01)
		a := dst.Addr.As4()
		out = append(out, a[:]...)
	default:
		out = append(out, 0x04)
		a := dst.Addr.As16()
		out = append(out, a[:]...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], dst.Port)
	return append(out, pb[:]...)
}

// streamWrap 把 vendored 栈产出的 net.Conn 抬成 link.Stream(补 Unwrap)。
type streamWrap struct {
	net.Conn
	below any
}

func (s *streamWrap) Unwrap() any { return s.below }
