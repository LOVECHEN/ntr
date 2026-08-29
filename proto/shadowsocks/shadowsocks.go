// Package shadowsocks 把 Shadowsocks-2022(2022-blake3-*)接入 NTR 的统一协议插件契约。
//
// ★用第三方权威实现:客户端/服务端都走 github.com/metacubex/sing-shadowsocks 的
// shadowaead_2022(与 Xray / mihomo / sing-box 线级互通)。SS 自包含 AEAD,无需下层传输,
// 故栈就是 [shadowsocks] 一层。auth 靠 method+password(sing 内部处理),NTR 归 Ambient。
package shadowsocks

import (
	"context"
	"fmt"
	"net"
	"strings"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	M "github.com/metacubex/sing/common/metadata"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/spec"
)

var (
	_ proxy.Server = (*Proxy)(nil)
	_ proxy.Client = (*Proxy)(nil)
)

const defaultMethod = "2022-blake3-aes-128-gcm"

// Config 是 Shadowsocks 自有配置。Password 是 base64 的密钥(长度按 method 定,sing 校验)。
// UDPoverTCP 开启后出站 UDP 走 uot(over-stream,与 sing-box/mihomo udp_over_tcp 互通)。
type Config struct {
	Method     string
	Password   string
	UDPoverTCP bool
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	m := n.Get("method").Str()
	if m == "" {
		m = defaultMethod
	}
	return Config{Method: m, Password: n.Get("password").Str(), UDPoverTCP: n.Get("udp-over-tcp").Bool()}, nil
}

// Proxy 是 SS 连接级句柄:客户端 Method + 服务端 Service 都在 Build 时建好、连接级复用。
type Proxy struct {
	cfg     Config
	method  shadowsocks.Method  // 客户端
	service shadowsocks.Service // 服务端(共享,含 replay filter)
}

// Build 构造 Proxy(建客户端 Method + 服务端 Service)。按 method 前缀分派两代:
// "2022-blake3-*" → shadowaead_2022(带 EIH 多用户 + 强 replay);其余(aes-256-gcm、
// chacha20-ietf-poly1305 等)→ 经典 shadowaead(口令经 EVP_BytesToKey 派生密钥)。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	method := cfg.Method
	if method == "" {
		method = defaultMethod
	}
	var cm shadowsocks.Method
	var svc shadowsocks.Service
	var err error
	if strings.HasPrefix(method, "2022-") {
		if cm, err = shadowaead_2022.NewWithPassword(method, cfg.Password, nil); err != nil {
			return nil, fmt.Errorf("shadowsocks: 客户端 method 失败:%w", err)
		}
		if svc, err = shadowaead_2022.NewServiceWithPassword(method, cfg.Password, 300, captureHandler{}, nil); err != nil {
			return nil, fmt.Errorf("shadowsocks: 服务端 service 失败:%w", err)
		}
	} else {
		if cm, err = shadowaead.New(method, nil, cfg.Password); err != nil {
			return nil, fmt.Errorf("shadowsocks: 客户端 method 失败:%w", err)
		}
		if svc, err = shadowaead.NewService(method, nil, cfg.Password, 300, captureHandler{}); err != nil {
			return nil, fmt.Errorf("shadowsocks: 服务端 service 失败:%w", err)
		}
	}
	p := &Proxy{cfg: Config{Method: method, Password: cfg.Password}, method: cm, service: svc}
	if cfg.UDPoverTCP {
		// UoT 变体:出站 UDP 走 over-stream(uot),不实现 NativePacketConnClient → upstream 自动走 UoT。
		return &uotProxy{inner: p}, nil
	}
	return p, nil
}

// ClientHandshake 实现 proxy.Client:在下层 stream 上写 SS 请求头,返回承载 payload 的 stream。
func (p *Proxy) ClientHandshake(_ context.Context, below link.Stream, _ []byte, dst addr.Socksaddr) (link.Stream, error) {
	conn, err := p.method.DialConn(below, toSing(dst))
	if err != nil {
		return nil, err
	}
	return &streamWrap{Conn: conn, below: below}, nil
}

// toSing / toNTR:两边 Socksaddr 字段同构({Addr,Port,Fqdn}),直转。
func toSing(a addr.Socksaddr) M.Socksaddr { return M.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn} }
func toNTR(a M.Socksaddr) addr.Socksaddr { return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn} }

// streamWrap 把 sing 的 net.Conn 抬成 link.Stream(补 Unwrap)。
type streamWrap struct {
	net.Conn
	below any
}

func (s *streamWrap) Unwrap() any { return s.below }
