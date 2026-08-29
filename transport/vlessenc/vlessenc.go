// Package vlessenc 把 VLESS Encryption(Xray 的后量子加密层,ML-KEM-768 + X25519)接入 NTR 作
// crypto 传输(BandCrypto,叠法 [vlessenc, vless] 或 [tls, vlessenc, vless])。核心协议 vendored
// 自 xtls/xray-core(internal/vlessenc),这里只做 NTR StreamTransport 接线 —— 客户端 ClientWrap
// 用公钥握手,服务端 ServerWrap 用私钥握手。禁改线格式。
//
// 配置(对齐 xray encryption/decryption 语义):
//   - key/keys:base64-rawurl 密钥。客户端(出站)=公钥(32=X25519 / 1184=ML-KEM-768 encap);
//     服务端(入站)=私钥(32=X25519 / 64=ML-KEM-768 seed)。keys 为 relay 链(多跳),优先于 key。
//   - mode:native(默认,xorMode 0)/ xorpub(1)/ random(2)。
//   - padding:xray padding 参数串(可空,用库默认)。
//   - zero-rtt:客户端 0-RTT(seconds=1);服务端 seconds 指定 ticket 有效期(启用 0-RTT 接受)。
package vlessenc

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sync"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
	enc "github.com/LOVECHEN/ntr/internal/vlessenc"
)

// Config 是 VLESS Encryption 传输配置。
type Config struct {
	Keys    []string // base64-rawurl 密钥链(客户端公钥 / 服务端私钥)
	Mode    string   // native / xorpub / random
	Padding string
	ZeroRTT bool // 客户端 0-RTT
	Seconds int  // 服务端 ticket 有效期(秒);>0 启用 0-RTT 接受
}

// Parse 从哑节点解出 Config。key 单密钥 / keys 密钥链;mode 缺省 native。
func Parse(n *spec.Node) (Config, error) {
	c := Config{
		Mode:    n.Get("mode").Str(),
		Padding: n.Get("padding").Str(),
		ZeroRTT: n.Get("zero-rtt").Bool(),
		Seconds: n.Get("seconds").Int(0),
	}
	if k := n.Get("key").Str(); k != "" {
		c.Keys = []string{k} // 单密钥(常见);relay 链为高级特性,后续增量
	}
	if c.Mode == "" {
		c.Mode = "native"
	}
	return c, nil
}

func xorMode(mode string) (uint32, error) {
	switch mode {
	case "", "native":
		return 0, nil
	case "xorpub":
		return 1, nil
	case "random":
		return 2, nil
	default:
		return 0, fmt.Errorf("vlessenc: 未知 mode %q(native/xorpub/random)", mode)
	}
}

func decodeKeys(keys []string) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("vlessenc: 缺 key/keys")
	}
	out := make([][]byte, 0, len(keys))
	for _, k := range keys {
		b, err := base64.RawURLEncoding.DecodeString(k)
		if err != nil {
			return nil, fmt.Errorf("vlessenc: 密钥 base64:%w", err)
		}
		out = append(out, b)
	}
	return out, nil
}

// Transport 是 VLESS Encryption 传输句柄。ClientInstance/ServerInstance 按 Wrap 方向懒建(缓存)。
type Transport struct {
	cfg    Config
	xm     uint32
	mu     sync.Mutex
	client *enc.ClientInstance
	server *enc.ServerInstance
}

// Build 构造 Transport(校验 mode;实例懒建)。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	xm, err := xorMode(cfg.Mode)
	if err != nil {
		return nil, err
	}
	return &Transport{cfg: cfg, xm: xm}, nil
}

func (t *Transport) getClient() (*enc.ClientInstance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		return t.client, nil
	}
	keys, err := decodeKeys(t.cfg.Keys)
	if err != nil {
		return nil, err
	}
	seconds := uint32(0)
	if t.cfg.ZeroRTT {
		seconds = 1
	}
	ci := &enc.ClientInstance{}
	if err := ci.Init(keys, t.xm, seconds, t.cfg.Padding); err != nil {
		return nil, fmt.Errorf("vlessenc: 客户端 init:%w", err)
	}
	t.client = ci
	return ci, nil
}

func (t *Transport) getServer() (*enc.ServerInstance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.server != nil {
		return t.server, nil
	}
	keys, err := decodeKeys(t.cfg.Keys)
	if err != nil {
		return nil, err
	}
	si := &enc.ServerInstance{}
	if err := si.Init(keys, t.xm, 0, int64(t.cfg.Seconds), t.cfg.Padding); err != nil {
		return nil, fmt.Errorf("vlessenc: 服务端 init:%w", err)
	}
	t.server = si
	return si, nil
}

// ClientWrap 实现 StreamTransport:用公钥跑客户端握手,返回加密流。
func (t *Transport) ClientWrap(_ context.Context, below link.Stream) (link.Stream, error) {
	ci, err := t.getClient()
	if err != nil {
		return nil, err
	}
	conn, err := ci.Handshake(below)
	if err != nil {
		return nil, fmt.Errorf("vlessenc: 客户端握手:%w", err)
	}
	return &connStream{Conn: conn, below: below}, nil
}

// ServerWrap 实现 StreamTransport:用私钥跑服务端握手,返回解密流。
func (t *Transport) ServerWrap(_ context.Context, below link.Stream) (link.Stream, error) {
	si, err := t.getServer()
	if err != nil {
		return nil, err
	}
	conn, err := si.Handshake(below, nil)
	if err != nil {
		return nil, fmt.Errorf("vlessenc: 服务端握手:%w", err)
	}
	return &connStream{Conn: conn, below: below}, nil
}

// connStream 把 vendored CommonConn(net.Conn)抬成 link.Stream(补 Unwrap)。
type connStream struct {
	net.Conn
	below link.Stream
}

func (c *connStream) Unwrap() any { return c.below }

var _ link.Stream = (*connStream)(nil)
