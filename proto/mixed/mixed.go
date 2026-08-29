// Package mixed 实现 socks + http 同端口共存的入站(sing-box/mihomo 称 mixed)。
//
// 它自身没有线格式 —— 只做一件事:窥视首字节决定分派,然后把【未消耗的原始流】原样交给
// socks 或 http 插件去跑各自的握手。故对两个被复用协议的线格式零影响。
//
//	首字节 0x04 → SOCKS4/4a    0x05 → SOCKS5    其它 → HTTP(CONNECT 或明文转发)
//
// ★ 复用而非重写:直接持有 proto/socks 与 proto/httpproxy 的实例。门禁只禁止
// core/service/outbound/reverse/muxcool import proto/*,协议插件之间互相复用是允许的。
package mixed

import (
	"bufio"
	"context"
	"errors"
	"io"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/proto/httpproxy"
	"github.com/LOVECHEN/ntr/proto/socks"
)

var (
	_ proxy.Server           = (*Proxy)(nil)
	_ proxy.PacketConnServer = (*Proxy)(nil)
)

const (
	socks4Version = 0x04
	socks5Version = 0x05
)

// errEmptyStream 表示连接建立后未发送任何字节(无法判定协议)。
var errEmptyStream = errors.New("mixed: 首字节读取失败,无法判定 socks/http")

// Config 是 mixed 配置(无自有参数)。
type Config struct{}

// Parse 从哑节点解出 Config。
func Parse(*spec.Node) (Config, error) { return Config{}, nil }

// Proxy 是 mixed 入站:按首字节把连接分派给 socks 或 http。
type Proxy struct {
	socks proxy.Server
	http  proxy.Server
}

// Build 构造 mixed 实例(内部各建一个 socks 与 http 插件实例)。
func Build(ctx context.Context, _ Config, _ any) (any, error) {
	sv, err := socks.Build(ctx, socks.Config{}, nil)
	if err != nil {
		return nil, err
	}
	hv, err := httpproxy.Build(ctx, httpproxy.Config{}, nil)
	if err != nil {
		return nil, err
	}
	s, ok := sv.(proxy.Server)
	if !ok {
		return nil, errors.New("mixed: socks 插件未实现 proxy.Server")
	}
	h, ok := hv.(proxy.Server)
	if !ok {
		return nil, errors.New("mixed: http 插件未实现 proxy.Server")
	}
	return &Proxy{socks: s, http: h}, nil
}

// ServerHandshake 窥视首字节后分派。被分派方拿到的流首字节【未被消耗】,
// 因此它们各自的握手逻辑与线格式完全不用改。
func (p *Proxy) ServerHandshake(ctx context.Context, below link.Stream, auth proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	br := bufio.NewReader(below)
	head, err := br.Peek(1)
	if err != nil {
		if err == io.EOF {
			return nil, nil, errEmptyStream
		}
		return nil, nil, err
	}
	st := &peekStream{Stream: below, br: br}
	switch head[0] {
	case socks4Version, socks5Version:
		return p.socks.ServerHandshake(ctx, st, auth)
	default: // HTTP 方法首字母(CONNECT/GET/POST…)一律交给 http 插件
		return p.http.ServerHandshake(ctx, st, auth)
	}
}

// ServerPacketConn 把 socks 分派出的 UDP-ASSOCIATE stream 交回 socks 子插件的 PacketConnServer
// 能力。SOCKS5 UDP 走 mixed 时,ServerHandshake 已把连接分派给 socks 并原样返回其 udpAssocStream;
// 此处仅转发能力,不触碰任何线格式。仅 socks 子插件具备该能力(http 无 UDP)。
func (p *Proxy) ServerPacketConn(below link.Stream, dst addr.Socksaddr) (link.PacketConn, error) {
	pcs, ok := p.socks.(proxy.PacketConnServer)
	if !ok {
		return nil, errors.New("mixed: socks 子插件不具备 PacketConnServer 能力")
	}
	return pcs.ServerPacketConn(below, dst)
}

// peekStream 把窥视用的 bufio 接回读路径,保证被分派方读到完整的原始流。
type peekStream struct {
	link.Stream
	br *bufio.Reader
}

func (s *peekStream) Read(p []byte) (int, error) { return s.br.Read(p) }
func (s *peekStream) Unwrap() any                { return s.Stream }
