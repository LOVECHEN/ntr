// Package snell 把 Snell v6 引擎(proto/snell/internal/snellv6,vendored 自校准过的
// go-snell-v6)接入 NTR 的统一协议插件契约(core/proxy)。协议是插件 —— inbound/relay/路由
// 只认 proxy.Server/proxy.Client,零 snell 特判。
//
// ★多用户模型(符合 ssmu / go-snell-v6):每个 snell 入站【单端口 PSK】做认证与加密(O(1)),
// 用户身份靠命令里的 clientID → CredID(经 Authenticator)。obfs/mode 是 snell 本体参数,非独立层。
package snell

import (
	"context"
	"net"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv123"
	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv45"
	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv6"
)

// 编译期断言:Snell 作为纯插件实现统一契约。
var (
	_ proxy.Server = (*Proxy)(nil)
	_ proxy.Client = (*Proxy)(nil)
)

// Config 是 Snell 协议自有配置。PSK 是端口级密钥(单端口 PSK);出站时客户端出示的凭据
// 由 ClientHandshake 的 key 传入。Version 选协议版本:1/2/3 走 snellv123(shadowsocks-AEAD 分帧,
// v1=chacha、v2/v3=aes128,mihomo v1-5 互通),4/5 走 snellv45(mihomo/官方 v4/v5 互通),
// 6(默认)走 snellv6(最新,带流量混淆 mode)。
type Config struct {
	PSK     []byte       // 端口级 PSK(服务端认证 + 加密)
	Version int          // 1-6(默认 6);1-3 走旧框架,4/5 同格式,6 最新
	Mode    snellv6.Mode // v6 加密模式(default/unshaped/unsafe-raw),须与对端一致
	ChaCha  bool         // v6 wire cipher;默认 AES-128-GCM(v4/v5 恒 AES-128)
}

// Parse 从哑配置节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	mode, _ := snellv6.ParseMode(n.Get("mode").Str()) // 缺省 → ModeDefault
	return Config{
		PSK:     []byte(n.Get("psk").Str()),
		Version: n.Get("version").Int(6), // 缺省 v6
		Mode:    mode,
		ChaCha:  n.Get("cipher").Str() == "chacha20-ietf-poly1305",
	}, nil
}

// isV45 报告是否走 v4/v5 引擎。
func (p *Proxy) isV45() bool { return p.cfg.Version == 4 || p.cfg.Version == 5 }

// isV123 报告是否走 v1/v2/v3 引擎(shadowsocks-AEAD 分帧)。
func (p *Proxy) isV123() bool { return p.cfg.Version >= 1 && p.cfg.Version <= 3 }

// v123ChaCha:v1 用 ChaCha20(32B key),v2/v3 用 AES-128-GCM(16B)。
func (p *Proxy) v123ChaCha() bool { return p.cfg.Version == 1 }

// v123ConnectCmd:v2 的 CONNECT 用 ConnectV2(0x05),v1/v3 用 CONNECT(0x01)。
func (p *Proxy) v123ConnectCmd() byte {
	if p.cfg.Version == 2 {
		return snellv123.CmdConnectReuse
	}
	return snellv123.CmdConnect
}

// Proxy 是 Snell 的连接级句柄(Descriptor.Build 产物)。
type Proxy struct {
	cfg Config
}

// Build 构造 Proxy(承 registry.Descriptor.Build)。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	return &Proxy{cfg: cfg}, nil
}

// ClientHandshake 实现 proxy.Client:在下层 stream 上跑 Snell v6 CONNECT 握手,出示 key(PSK),
// 返回承载中继 payload 的 link.Stream。
func (p *Proxy) ClientHandshake(_ context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.Stream, error) {
	psk := key
	if len(psk) == 0 {
		psk = p.cfg.PSK
	}
	if p.isV123() { // v1/v2/v3:shadowsocks-AEAD 分帧,与 mihomo(version 1-5)线级互通
		rc, err := (&snellv123.Client{PSK: psk, ChaCha: p.v123ChaCha(), ConnectCmd: p.v123ConnectCmd()}).
			DialTCPOver(below, dst.Host(), dst.Port, nil)
		if err != nil {
			return nil, err
		}
		return &streamWrap{Conn: rc, below: below}, nil
	}
	if p.isV45() { // v4/v5:与 mihomo/官方 Snell 线级互通
		rc, err := (&snellv45.Client{PSK: psk}).DialTCPOver(below, dst.Host(), dst.Port, nil)
		if err != nil {
			return nil, err
		}
		return &streamWrap{Conn: rc, below: below}, nil
	}
	c := &snellv6.Client{PSK: psk, ChaCha: p.cfg.ChaCha, Mode: p.cfg.Mode}
	rc, err := c.DialTCPOver(below, dst.Host(), dst.Port, nil)
	if err != nil {
		return nil, err
	}
	return &streamWrap{Conn: rc, below: below}, nil
}

// streamWrap 把 snellv6 返回的 net.Conn 包成 link.Stream(补 Unwrap 供能力发现)。
type streamWrap struct {
	net.Conn
	below any
}

func (s *streamWrap) Unwrap() any { return s.below }
