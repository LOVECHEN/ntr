// Package shadowtls 把 ShadowTLS(v2/v3)接入 NTR 的传输层契约(core/transport.StreamTransport)。
//
// ★用第三方权威实现 github.com/sagernet/sing-shadowtls(与 mihomo/sing-box 互通)。ShadowTLS
// 是「伪装成对真站的 TLS 握手」的传输层:客户端 DialContextConn 在下层 stream 上做真 TLS 握手
// (SNI=伪装域,握手被服务端中继到真站),鉴权后切到承载内层协议的 stream;服务端 Service 把
// 外层握手中继到真 TLS 站(Handshake dest,类 REALITY 的 dest),鉴权通过后把内层 stream 交上层。
//
// ShadowTLS 本身只提供「抗主动探测的伪装 + 完整性」,不保证内层机密性 → 不 Provides SecureCarrier,
// 惯用叠法是 [shadowtls, shadowsocks](SS 自带 AEAD)。栈里它占 CryptoObfs band(伪装槽)。
package shadowtls

import (
	"context"
	cryptotls "crypto/tls"
	"errors"
	"net"

	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
)

// Config 是 ShadowTLS 层自有配置。
type Config struct {
	Version   int    // 2 或 3(默认 3)
	Password  string // 鉴权口令
	SNI       string // 伪装域名(客户端 ServerName;服务端握手中继目标默认取 SNI:443)
	Handshake string // 服务端:外层握手中继到的真 TLS 站 host:port(留空 → SNI:443)
	Insecure  bool   // 客户端:跳过对真站证书校验(自签测试用)
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	return Config{
		Version:   n.Get("version").Int(3),
		Password:  n.Get("password").Str(),
		SNI:       n.Get("sni").Str(),
		Handshake: n.Get("handshake").Str(),
		Insecure:  n.Get("insecure").Bool(),
	}, nil
}

// Transport 是 ShadowTLS 传输层句柄:客户端 Client + 服务端 Service 都在 Build 时建好、连接级复用。
type Transport struct {
	client  *shadowtls.Client
	service *shadowtls.Service
}

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	version := cfg.Version
	if version == 0 {
		version = 3
	}
	handshakeDest := cfg.Handshake
	if handshakeDest == "" && cfg.SNI != "" {
		handshakeDest = cfg.SNI + ":443"
	}

	// 客户端:真 TLS 握手(伪装 SNI),鉴权注入由 DefaultTLSHandshakeFunc 完成。
	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:      version,
		Password:     cfg.Password,
		Server:       M.ParseSocksaddr(handshakeDest), // 仅占位(DialContextConn 用下层 conn)
		Dialer:       N.SystemDialer,
		StrictMode:   false,
		TLSHandshake: shadowtls.DefaultTLSHandshakeFunc(cfg.Password, &cryptotls.Config{ServerName: cfg.SNI, InsecureSkipVerify: cfg.Insecure, MinVersion: cryptotls.VersionTLS12}),
		Logger:       logger.NOP(),
	})
	if err != nil {
		return nil, err
	}

	// 服务端:把外层握手中继到真 TLS 站,鉴权通过后把内层 stream 交 captureHandler。
	svcCfg := shadowtls.ServiceConfig{
		Version:   version,
		Handshake: shadowtls.HandshakeConfig{Server: M.ParseSocksaddr(handshakeDest), Dialer: N.SystemDialer},
		Handler:   captureHandler{},
		Logger:    logger.NOP(),
	}
	if version == 3 {
		svcCfg.Users = []shadowtls.User{{Name: "u", Password: cfg.Password}}
	} else {
		svcCfg.Password = cfg.Password
	}
	service, err := shadowtls.NewService(svcCfg)
	if err != nil {
		return nil, err
	}
	return &Transport{client: client, service: service}, nil
}

// ClientWrap 实现 StreamTransport:在下层 stream 上做 ShadowTLS 客户端握手,返回内层承载 stream。
func (t *Transport) ClientWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	conn, err := t.client.DialContextConn(ctx, below)
	if err != nil {
		return nil, err
	}
	return &streamWrap{Conn: conn, below: below}, nil
}

// ServerWrap 实现 StreamTransport:跑 ShadowTLS 服务端握手(中继到真站 + 鉴权),同步捕获内层
// stream。Service.NewConnection 在握手 + 鉴权后同步调 handler(不 spawn、不关内层 conn),故可捕获。
func (t *Transport) ServerWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	r := &result{}
	cctx := context.WithValue(ctx, resultKey{}, r)
	src := M.SocksaddrFromNet(below.RemoteAddr())
	if err := t.service.NewConnection(cctx, below, src, M.Socksaddr{}, nil); err != nil {
		return nil, err
	}
	if r.conn == nil {
		return nil, errors.New("shadowtls: 未捕获到内层连接(鉴权失败或被劫持流量)")
	}
	return &streamWrap{Conn: r.conn, below: below}, nil
}

// resultKey / result / captureHandler:同步捕获内层 stream(同 SS/AnyTLS 的 ctx 键法)。
type resultKey struct{}

type result struct{ conn net.Conn }

type captureHandler struct{}

func (captureHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	if r, ok := ctx.Value(resultKey{}).(*result); ok {
		r.conn = conn
	}
}

type streamWrap struct {
	net.Conn
	below any
}

func (s *streamWrap) Unwrap() any { return s.below }
