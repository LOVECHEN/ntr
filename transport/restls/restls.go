// Package restls 把 REST-TLS(restls)接入 NTR 的传输层契约(core/transport.StreamTransport)。
//
// ★用第三方权威实现 github.com/metacubex/restls-client-go(mihomo 同库 → 线级互通)。restls 是
// ShadowTLS 的进阶抗探测伪装:客户端用 uTLS 对【真站】做一次真实 TLS 1.3 握手(SNI=伪装域),服务端把
// 握手全程中继到那台真站;鉴权(共享 password 派生)通过后,双方切到「把代理数据伪装成 TLS 记录」的
// 承载流。主动探测者只会看到一个到真站的正常 TLS 连接,被引流到真站、拿不到任何代理特征。
//
// 与 ShadowTLS 同槽:只提供抗探测伪装 + 完整性、不保证内层机密性 → 惯用叠法 [restls, shadowsocks]
// (SS 自带 AEAD)。占 CryptoObfs band。restls 仅 mihomo 支持 → 交叉验证对 mihomo。
package restls

import (
	"context"
	"net"

	restls "github.com/metacubex/restls-client-go"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
)

// Config 是 restls 层自有配置。
type Config struct {
	ServerName   string // SNI / 伪装真站域名(客户端 ServerName;服务端中继握手的目标,无端口默认 :443)
	Password     string // 共享口令(派生流量鉴权密钥)
	VersionHint  string // 版本提示(默认 tls13)
	RestlsScript string // 记录尺寸 / 假响应脚本(可空 → 库默认)
	Fingerprint  string // 客户端 uTLS 指纹(chrome/firefox/…;默认 chrome)
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	return Config{
		ServerName:   n.Get("server-name").Str(),
		Password:     n.Get("password").Str(),
		VersionHint:  n.Get("version-hint").Str(),
		RestlsScript: n.Get("restls-script").Str(),
		Fingerprint:  n.Get("fingerprint").Str(),
	}, nil
}

// Transport 是 restls 传输层句柄:客户端 config 模板 + 服务端 config 都在 Build 时建好、连接级复用。
type Transport struct {
	clientCfg *restls.Config
	serverCfg *restls.RestlsServerConfig
}

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	version := cfg.VersionHint
	if version == "" {
		version = "tls13"
	}
	fp := cfg.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	// 客户端 config 模板(每连接 Clone 后握手,避免 race)。
	clientCfg, err := restls.NewRestlsConfig(cfg.ServerName, cfg.Password, version, cfg.RestlsScript, fp)
	if err != nil {
		return nil, err
	}
	// 服务端 config:把外层握手中继到真站(ServerName,无端口库自动补 :443),鉴权后交内层承载。
	serverCfg := &restls.RestlsServerConfig{
		ServerHostname: cfg.ServerName,
		Password:       cfg.Password,
		RestlsScript:   cfg.RestlsScript,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	return &Transport{clientCfg: clientCfg, serverCfg: serverCfg}, nil
}

// ClientWrap 实现 StreamTransport:在下层 stream 上做 restls(uTLS)客户端握手,返回内层承载 stream。
func (t *Transport) ClientWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	cfg := t.clientCfg.Clone() // 避免 HandshakeContext 的并发 race(同 mihomo NewRestls)
	helloID := restls.HelloChrome_Auto
	if p := cfg.ClientID.Load(); p != nil {
		helloID = *p
	}
	uc := restls.UClient(below, cfg, helloID)
	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return &streamWrap{Conn: uc, below: below}, nil
}

// ServerWrap 实现 StreamTransport:跑 restls 服务端握手(中继到真站 + 鉴权),返回内层承载 stream。
// 未鉴权/探测流量会被库引流到真站(fallback),此时 RestlsServer 返回错误 → 上层收尾。
func (t *Transport) ServerWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	conn, err := restls.RestlsServer(ctx, below, t.serverCfg)
	if err != nil {
		return nil, err
	}
	return &streamWrap{Conn: conn, below: below}, nil
}

// streamWrap 把 restls 的 net.Conn 抬成 link.Stream(Unwrap 返回下层,供能力发现)。
type streamWrap struct {
	net.Conn
	below any
}

func (s *streamWrap) Unwrap() any { return s.below }
