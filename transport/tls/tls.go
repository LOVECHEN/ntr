// Package tls 是 TLS 传输层(承设计第 3 章 §3.1.1,Band=Crypto)。
//
// 它实现 transport.StreamTransport:Stream→Stream 变换,同一个 Descriptor 覆盖入站
// (ServerWrap)与出站(ClientWrap)。对上层协议无感知 —— vless/trojan 叠在它之上时,
// 只是把"下层 stream"从裸 TCP 换成 TLS record 流,握手/中继逻辑一字不改。
package tls

import (
	"context"
	cryptotls "crypto/tls"
	"net"

	utls "github.com/refraction-networking/utls"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/transport"
)

// Transport 是构建产物:握手所需的双向 *tls.Config 各一份(Build 时定,连接级复用)。
type Transport struct {
	server      *cryptotls.Config
	client      *cryptotls.Config
	useUTLS     bool               // 客户端是否走 uTLS 指纹仿真
	fingerprint utls.ClientHelloID // useUTLS 时的 ClientHello 指纹
}

var _ transport.StreamTransport = (*Transport)(nil)

// ServerWrap 用服务端证书完成 TLS 握手,返回承载明文的 Stream。
func (t *Transport) ServerWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	c := cryptotls.Server(below, t.server)
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return &stream{Conn: c, below: below}, nil
}

// ClientWrap 以 ServerName/校验策略发起 TLS 握手。配了 fingerprint 则走 uTLS 仿真真实浏览器
// ClientHello(抗 TLS 指纹审查),否则标准 crypto/tls。
func (t *Transport) ClientWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	if t.useUTLS {
		uConn := utls.UClient(below, &utls.Config{
			ServerName:         t.client.ServerName,
			InsecureSkipVerify: t.client.InsecureSkipVerify,
			NextProtos:         t.client.NextProtos,
			MinVersion:         t.client.MinVersion,
		}, t.fingerprint)
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return &utlsStream{UConn: uConn, below: below}, nil
	}
	c := cryptotls.Client(below, t.client)
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return &stream{Conn: c, below: below}, nil
}

// stream 把 *tls.Conn 抬成 link.Stream;Unwrap 返回被包裹的下层供能力发现。
type stream struct {
	*cryptotls.Conn
	below any
}

func (s *stream) Unwrap() any { return s.below }

// TLSConn 暴露底层 *crypto/tls.Conn(实现 link.TLSConnCarrier)—— 供 VLESS Vision 反射做 splice。
func (s *stream) TLSConn() net.Conn { return s.Conn }

// utlsStream 把 uTLS 的 *utls.UConn 抬成 link.Stream。也实现 TLSConnCarrier(返回 UConn,net.Conn),
// 供 ALPN 等能力发现;但 Vision 反射需 *crypto/tls.Conn,故 uTLS 之上不支持 Vision(用 REALITY 承 Vision)。
type utlsStream struct {
	*utls.UConn
	below any
}

func (s *utlsStream) Unwrap() any       { return s.below }
func (s *utlsStream) TLSConn() net.Conn { return s.UConn }
