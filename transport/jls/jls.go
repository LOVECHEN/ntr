// Package jls 是 JLS 传输层(承设计第 3 章 Band=Crypto)—— JLS 是 REALITY 式的抗检测 TLS 变体:
// 客户端/服务端共享用户名+口令(PSK),在【改版 TLS 1.3 握手】里互认;认证通过 = 机密隧道,
// 认证失败(探测者无 PSK)= 服务端把连接【回落】到真实站点(dest),使主动探测看到的是一个真网站。
//
// ★线格式全在 github.com/metacubex/jls-tls(crypto/tls 的 JLS 改版分支,与 mihomo transport/jls 同源),
// 故对认证通过的对端,NTR 与 mihomo 的 JLS 握手【逐字节一致】。本包只桥该库,不改一字节线格式。
// 与 tls/shadowtls/reality 一样是 Stream→Stream 变换,vless/trojan 叠其上、握手中继逻辑不变。
//
// v1:客户端 + 服务端认证路径完整互通;服务端【回落 relay】(认证失败转发到 dest)为后续增量 ——
// 缺它只影响【对主动探测的隐蔽性】,不影响【已认证对端的线格式/互通】。当前认证失败即断开(诚实标注)。
package jls

import (
	"context"
	"errors"

	jlstls "github.com/metacubex/jls-tls"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/transport"
)

// ErrAuthFailed 表示 JLS 认证未通过(对端非合法 PSK 持有者)。
var ErrAuthFailed = errors.New("jls: 认证失败(peer 无合法 PSK)")

// Transport 是构建产物:握手所需的双向 *jlstls.Config 各一份(Build 时定,连接级 Clone 复用)。
type Transport struct {
	server *jlstls.Config
	client *jlstls.Config
}

var _ transport.StreamTransport = (*Transport)(nil)

// ServerWrap 用随机证书 + JLS PSK 完成握手。认证通过返回明文 Stream;失败即断开(v1 无回落 relay)。
func (t *Transport) ServerWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	c := jlstls.Server(below, t.server.Clone())
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if c.ConnectionState().JLS.Status != jlstls.JLSAuthenticated {
		return nil, ErrAuthFailed
	}
	return &stream{Conn: c, below: below}, nil
}

// ClientWrap 以 ServerName + JLS PSK 发起握手,并校验 JLS 认证态(对齐 mihomo:未认证即失败)。
func (t *Transport) ClientWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	c := jlstls.Client(below, t.client.Clone())
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if c.ConnectionState().JLS.Status != jlstls.JLSAuthenticated {
		return nil, ErrAuthFailed
	}
	return &stream{Conn: c, below: below}, nil
}

// stream 把 *jlstls.Conn 抬成 link.Stream;Unwrap 返回下层供能力发现。
type stream struct {
	*jlstls.Conn
	below any
}

func (s *stream) Unwrap() any { return s.below }
