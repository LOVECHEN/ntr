//go:build with_wireguard

// Package wireguard 把 WireGuard 接入 NTR:纯用户态 L3 隧道出站。
//
// ★ build tag 隔离:默认【不编入】瘦核心。它引入 golang.zx2c4.com/wireguard(MIT)与其
// tun/netstack 子包(内含 gVisor 用户态 TCP/IP 栈),实测编译进二进制的 module 有 6 个、
// 体积增量可观 —— 与 NTR「纯静态瘦核心」的默认形态冲突,故须显式 -tags with_wireguard 才带上。
// core/ 绝不 import 本包。
//
// 形态:WireGuard 是 L3(收发 IP 包),NTR 的代理契约是 L4(给 host:port 要一条流)。
// 中间靠 wireguard-go 自带的用户态 netstack 合成:
//
//	NTR DialStream(dst) → netstack.Net.DialContext → 合成 TCP SYN 等 IP 包
//	  → tun.Device → WireGuard device 加密 → UDP 发往 peer endpoint
//
// 这样 Device 形态被点亮,且不需要 NTR 自己实现 core/link.Device —— netstack 在
// wireguard-go 内部已把 IP 包泵成 net.Conn。
package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = (*Outbound)(nil)

const defaultMTU = 1408

// Options 是 WireGuard 出站配置。密钥可给 base64(wg-quick 风格)或 hex,内部统一转 hex。
type Options struct {
	PrivateKey    string   // 本端私钥(base64 44 字符 或 hex 64 字符)
	PeerPublicKey string   // 对端公钥
	PresharedKey  string   // 可选 PSK
	Endpoint      string   // 对端 host:port
	LocalAddress  []string // 本端隧道内地址(CIDR 或裸 IP),如 10.0.0.2/32
	AllowedIPs    []string // 允许经隧道的目标网段,默认 0.0.0.0/0 + ::/0
	DNS           []string // 隧道内 DNS(可空)
	MTU           int
	Keepalive     int // persistent_keepalive_interval 秒
}

// Outbound 是 WireGuard 出站:内部持一个用户态 WG device + netstack。
type Outbound struct {
	dev  *device.Device
	tnet *netstack.Net
	once sync.Once
}

// NewOutbound 构造并拉起 WireGuard 出站。
func NewOutbound(o Options) (*Outbound, error) {
	locals, err := parseAddrs(o.LocalAddress)
	if err != nil {
		return nil, fmt.Errorf("wireguard: local-address:%w", err)
	}
	if len(locals) == 0 {
		return nil, errors.New("wireguard: 需至少一个 local-address(隧道内本端 IP)")
	}
	dns, err := parseAddrs(o.DNS)
	if err != nil {
		return nil, fmt.Errorf("wireguard: dns:%w", err)
	}
	mtu := o.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	uapi, err := buildUAPI(o)
	if err != nil {
		return nil, err
	}

	tunDev, tnet, err := netstack.CreateNetTUN(locals, dns, mtu)
	if err != nil {
		return nil, fmt.Errorf("wireguard: 建用户态 TUN 失败:%w", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "ntr-wg "))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard: 配置失败:%w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard: 拉起失败:%w", err)
	}
	return &Outbound{dev: dev, tnet: tnet}, nil
}

// buildUAPI 把 Options 拼成 wireguard-go 的 uapi 文本。
// ★ 关键坑:wg-quick 配置里密钥是 base64(44 字符),但 UAPI 只吃 hex(64 字符),必须转换。
func buildUAPI(o Options) (string, error) {
	priv, err := toHexKey(o.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("wireguard: private-key:%w", err)
	}
	pub, err := toHexKey(o.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("wireguard: peer-public-key:%w", err)
	}
	if o.Endpoint == "" {
		return "", errors.New("wireguard: 缺 endpoint")
	}
	// ★ wireguard-go 默认 Bind 的 ParseEndpoint 只吃 IP:port,不解析域名,
	// 故此处先把域名解析成 IP(与 wg-quick 的行为一致)。
	ep, err := resolveEndpoint(o.Endpoint)
	if err != nil {
		return "", fmt.Errorf("wireguard: endpoint %q:%w", o.Endpoint, err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	fmt.Fprintf(&b, "public_key=%s\n", pub) // 切入 peer 段
	if o.PresharedKey != "" {
		psk, err := toHexKey(o.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("wireguard: preshared-key:%w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", ep)
	allowed := o.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	for _, a := range allowed {
		if _, err := netip.ParsePrefix(a); err != nil {
			return "", fmt.Errorf("wireguard: allowed-ip %q 非法:%w", a, err)
		}
		fmt.Fprintf(&b, "allowed_ip=%s\n", a)
	}
	if o.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", o.Keepalive)
	}
	return b.String(), nil
}

// toHexKey 把 base64(44 字符)或 hex(64 字符)密钥统一转成 UAPI 要的 hex。
func toHexKey(s string) (string, error) {
	if s == "" {
		return "", errors.New("为空")
	}
	if len(s) == 64 {
		if _, err := hex.DecodeString(s); err == nil {
			return strings.ToLower(s), nil
		}
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", errors.New("既非 64 字符 hex 也非 base64")
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("密钥应为 32 字节,得到 %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// resolveEndpoint 把 host:port 里的域名解析成 IP(wireguard-go 的 Bind 不做 DNS)。
// 优先 IPv4,没有再取 IPv6。
func resolveEndpoint(s string) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return s, nil // 已是 IP,原样用
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("解析域名失败:%w", err)
	}
	for _, ip := range ips { // 优先 IPv4
		if v4 := ip.To4(); v4 != nil {
			return net.JoinHostPort(v4.String(), port), nil
		}
	}
	if len(ips) > 0 {
		return net.JoinHostPort(ips[0].String(), port), nil
	}
	return "", errors.New("域名无解析结果")
}

// parseAddrs 解析地址列表,接受裸 IP 或 CIDR(取其地址部分)。
func parseAddrs(list []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Addr())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q 既非 IP 也非 CIDR", s)
		}
		out = append(out, a)
	}
	return out, nil
}

// DialStream 经隧道内 netstack 拨一条 TCP 到 dst。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	c, err := o.tnet.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, err
	}
	return connStream{c}, nil
}

// DialPacket 经隧道内 netstack 拨一条 UDP 到 dst(单目标)。
func (o *Outbound) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	c, err := o.tnet.DialContext(ctx, "udp", dst.String())
	if err != nil {
		return nil, err
	}
	return &udpConn{Conn: c, dst: dst}, nil
}

// Close 关闭 WireGuard device(幂等)。
func (o *Outbound) Close() error {
	o.once.Do(func() { o.dev.Close() })
	return nil
}

// connStream 把 netstack 的 net.Conn 抬成 link.Stream。
type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

// udpConn 把隧道内的连接式 UDP 抬成单目标 link.PacketConn。
type udpConn struct {
	net.Conn
	dst addr.Socksaddr
}

var _ link.PacketConn = (*udpConn)(nil)

func (c *udpConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	n, err := c.Read(b.ExtendTail(b.Tailroom()))
	if err != nil {
		return addr.Socksaddr{}, err
	}
	b.Truncate(n)
	return c.dst, nil
}

func (c *udpConn) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error {
	_, err := c.Write(b.Bytes())
	return err
}

func (c *udpConn) Unwrap() any { return c.Conn }
