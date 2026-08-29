// Package reality 把 XTLS REALITY 接入 NTR 的传输插件架构(Band=Crypto)。
//
// ★用第三方权威实现、协议完整符合原版:
//   - 服务端:直接用 github.com/xtls/reality 的 reality.Server(参考实现,借真站证书、
//     鉴权失败隐身回落到真实网站 Dest)——任何现网 Xray/sing-box REALITY 客户端可直连。
//   - 客户端:reality 库不含客户端认证注入(其 Client 走标准随机 sessionId),故按 Xray
//     的做法用 uTLS 复刻:x25519(临时私钥, 服务端公钥) → HKDF-SHA256(salt=random[:20],
//     "REALITY") → AES-GCM 把 [ver|time|shortId] 封进 ClientHello.sessionId(AAD=sessionId
//     置零后的 ClientHello),与服务端 tls.go 的校验逐字节对应。互通测试对 reality.Server
//     跑通即证明客户端认证字节精确(服务端只对通过鉴权的连接返回成功)。
//
// 对上层协议无感知:vless/trojan 叠在其上时,只是把下层从裸 TCP 换成 REALITY 流。
package reality

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"time"

	xreality "github.com/xtls/reality"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/transport"
)

var _ transport.StreamTransport = (*Transport)(nil)

// clientHelloSessionIDOffset 是 ClientHello 握手消息里 sessionId 的字节偏移
// (type1+len3+version2+random32=38 → sessionIdLen 在 38、sessionId 从 39 起)。
const clientHelloSessionIDOffset = 39

var (
	errNoServerConfig = errors.New("reality: 无服务端配置(缺 PrivateKey/Dest)")
	errNoClientConfig = errors.New("reality: 无客户端配置(缺 PublicKey/ServerName)")
	errNoX25519       = errors.New("reality: uTLS ClientHello 未产生 X25519 临时密钥")
)

// Transport 是构建产物:服务端 reality.Config + 客户端认证参数,连接级复用。
type Transport struct {
	server *xreality.Config // 服务端;nil = 不作服务端

	// 客户端认证参数;pubKey 为空 = 不作客户端。
	pubKey      []byte // 服务端 x25519 公钥(32)
	shortID     [8]byte
	serverName  string
	fingerprint utls.ClientHelloID
	clientVer   [4]byte
}

// ServerWrap 用参考实现完成 REALITY 服务端握手(鉴权 + 借证书 + 隐身回落全在库内)。
func (t *Transport) ServerWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	if t.server == nil {
		return nil, errNoServerConfig
	}
	rc, err := xreality.Server(ctx, baseConn(below), t.server)
	if err != nil {
		return nil, err
	}
	return &stream{Conn: rc, below: below}, nil
}

// ClientWrap 以 uTLS 复刻 REALITY 客户端认证:把鉴权封进 ClientHello.sessionId 后握手。
func (t *Transport) ClientWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	if len(t.pubKey) != 32 || t.serverName == "" {
		return nil, errNoClientConfig
	}
	uConfig := &utls.Config{
		ServerName:             t.serverName,
		InsecureSkipVerify:     true, // REALITY 不走 CA 链;信任锚是 pin 的服务端公钥
		SessionTicketsDisabled: true,
	}
	uConn := utls.UClient(below, uConfig, t.fingerprint)
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := uConn.HandshakeState.Hello

	ecdhe := clientEcdheKey(uConn)
	if ecdhe == nil {
		return nil, errNoX25519
	}
	authKey, err := curve25519.X25519(ecdhe.Bytes(), t.pubKey)
	if err != nil {
		return nil, err
	}
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, err
	}

	// 认证注入(与 Xray 一致):sessionId 字段与 hello.Raw 同步改。
	// 先置零(AAD = sessionId 置零后的 ClientHello,对齐服务端 aead.Open),填明文,seal 后写回。
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[clientHelloSessionIDOffset:], hello.SessionId) // 置零 raw 的 sessionId 区(AAD)
	copy(hello.SessionId[0:4], t.clientVer[:])
	binary.BigEndian.PutUint32(hello.SessionId[4:8], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:16], t.shortID[:])

	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw) // sessionId[0:32]=密文
	copy(hello.Raw[clientHelloSessionIDOffset:], hello.SessionId)                       // 密文写回 raw

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return &stream{Conn: uConn, below: below}, nil
}

// clientEcdheKey 取 uTLS ClientHello 的 X25519 临时私钥(兼容纯 X25519 与 X25519MLKEM768 混合)。
func clientEcdheKey(uConn *utls.UConn) *ecdh.PrivateKey {
	if ks := uConn.HandshakeState.State13.KeyShareKeys; ks != nil {
		if ks.Ecdhe != nil {
			return ks.Ecdhe // 纯 X25519 key share
		}
		if ks.MlkemEcdhe != nil {
			return ks.MlkemEcdhe // X25519MLKEM768 混合 key share 中的 X25519 分量
		}
	}
	//lint:ignore SA1019 老版 utls 向后兼容兜底:新版已走 KeyShareKeys(Ecdhe/MlkemEcdhe),此路径仅当二者皆空
	return uConn.HandshakeState.State13.EcdheKey
}

// baseConn 沿 Unwrap 链探到最底层 net.Conn(reality.Server 需要 *net.TCPConn 做 CloseWrite/splice)。
func baseConn(s link.Stream) net.Conn {
	var c net.Conn = s
	for {
		u, ok := c.(interface{ Unwrap() any })
		if !ok {
			return c
		}
		n, ok := u.Unwrap().(net.Conn)
		if !ok {
			return c
		}
		c = n
	}
}

// stream 把 REALITY/uTLS 的 net.Conn 抬成 link.Stream;Unwrap 返回下层供能力发现。
type stream struct {
	net.Conn
	below any
}

func (s *stream) Unwrap() any { return s.below }

// TLSConn 暴露底层 TLS 连接(uTLS / reality.Conn,实现 link.TLSConnCarrier)—— 供 VLESS Vision
// 反射做 splice。注:uTLS 类型需在 sing-vmess/vless 的 tlsRegistry 另行注册(Vision over REALITY 用)。
func (s *stream) TLSConn() net.Conn { return s.Conn }
