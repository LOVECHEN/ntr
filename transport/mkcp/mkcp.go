// Package mkcp 把 mKCP(Xray 的可靠-UDP 传输:KCP 变体 + header 伪装)接入 NTR 的 BaseTransport。
//
// mKCP 是【UDP-base】传输:底层是 UDP datagram,KCP 提供可靠有序流,其上再叠代理(vless 等)。
// 与 xray-core transport/internet/kcp / mihomo transport/mkcp 线级互通。
//
// ★引擎 vendored 自 mihomo transport/mkcp(自包含仅 stdlib,见 internal/mkcpcore),不新增模块依赖、
// 不改线格式;NTR 侧仅做 BaseTransport 封装(DialBase 拨 UDP + KCP;ListenBase UDP 监听 + KCP accept)。
// 占 BandBase,惯用叠法 [mkcp, vless] 或 [mkcp, tls, vless]。
package mkcp

import (
	"context"
	"net"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
	"github.com/LOVECHEN/ntr/transport/mkcp/internal/mkcpcore"
)

var _ transport.BaseTransport = (*Transport)(nil)

// Config 是 mKCP 层配置。Header 是 UDP 包伪装类型(none/srtp/utp/wechat-video/dtls/wireguard),
// Seed 是可选混淆密钥;两端须一致。容量/MTU 等按 xray 默认。
type Config struct {
	Header string
	Seed   string
	MTU    uint32
	TTI    uint32
	Up     uint32
	Down   uint32
	Cong   bool
}

// Parse 从哑节点解出 Config。缺省对齐 xray(MTU 1350、TTI 50、上/下行 5/20 Mbps、无拥塞控制、header none)。
func Parse(n *spec.Node) (Config, error) {
	return Config{
		Header: n.Get("header").Str(),
		Seed:   n.Get("seed").Str(),
		MTU:    uint32(n.Get("mtu").Int(1350)),
		TTI:    uint32(n.Get("tti").Int(50)),
		Up:     uint32(n.Get("uplink-capacity").Int(5)),
		Down:   uint32(n.Get("downlink-capacity").Int(20)),
		Cong:   n.Get("congestion").Bool(),
	}, nil
}

// Transport 是 mKCP 传输句柄(连接级复用配置)。
type Transport struct{ cfg mkcpcore.Config }

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	return &Transport{cfg: mkcpcore.Config{
		MTU: cfg.MTU, TTI: cfg.TTI, UplinkCapacity: cfg.Up, DownlinkCapacity: cfg.Down,
		Congestion: cfg.Cong, Seed: cfg.Seed, Header: cfg.Header,
	}}, nil
}

// DialBase 实现 BaseTransport:拨 UDP socket 到 server,套 KCP,返回可靠 link.Stream。
func (t *Transport) DialBase(ctx context.Context, server string) (link.Stream, error) {
	raw, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	kc, err := mkcpcore.Dial(ctx, raw, t.cfg)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return connStream{kc}, nil
}

// ListenBase 实现 BaseTransport:UDP 监听 + KCP accept,返回 BaseListener(每 Accept 出一条 KCP 流)。
func (t *Transport) ListenBase(ctx context.Context, listen string) (transport.BaseListener, error) {
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return nil, err
	}
	l, err := mkcpcore.Listen(ctx, pc, t.cfg)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return &kcpListener{l: l}, nil
}

// kcpListener 把 mkcpcore.Listener 抬成 transport.BaseListener(Accept 出 link.Stream)。
type kcpListener struct{ l *mkcpcore.Listener }

func (k *kcpListener) Accept() (link.Stream, error) {
	c, err := k.l.Accept()
	if err != nil {
		return nil, err
	}
	return connStream{c}, nil
}
func (k *kcpListener) Close() error   { return k.l.Close() }
func (k *kcpListener) Addr() net.Addr { return k.l.Addr() }

// connStream 把 KCP net.Conn 抬成 link.Stream(补 Unwrap)。
type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

var _ link.Stream = connStream{}

// 编译期兜底:确保 SetDeadline 等 net.Conn 方法齐全(mkcpcore.Conn 已实现)。
var _ interface {
	SetDeadline(time.Time) error
} = (*mkcpcore.Conn)(nil)
