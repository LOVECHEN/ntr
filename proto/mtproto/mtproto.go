// Package mtproto 实现 Telegram 的 MTProto proxy 协议(ee / faketls 模式)。
//
// ★ 照公开线格式【自写】,零新依赖 —— 不引 9seconds/mtg 的 mtglib(它会拖进 prometheus/kong/
// socks5/ntp 等 30+ 依赖,违反 NTR 瘦核心)。线格式与 mtg v2.2.8 逐字节对齐。
//
// 分层(外 → 内):
//
//	TCP → faketls(TLS 1.3 外形;ClientHello/ServerHello 的 32 字节 random 兼作 HMAC 凭据,
//	              建立后双向封 ApplicationData 记录)
//	    → obfuscated2(64 字节握手帧派生双向 AES-256-CTR,帧内带 DC 索引)
//	        → MTProto 载荷(原样中继到 Telegram DC)
//
// 语义注意:MTProto proxy 不是通用 CONNECT 代理 —— 客户端只带 DC 索引,不指定任意目标。
// 服务端据 DC 索引把 Request.Dst 【合成】为对应 Telegram DC 地址(内置公开表,可配置覆盖)。
package mtproto

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/spec"
)

var (
	_ proxy.Server = (*Proxy)(nil)
	_ proxy.Client = (*Proxy)(nil)
)

// secretFakeTLSFirstByte 是 ee(faketls)secret 的固定首字节。
const secretFakeTLSFirstByte = 0xee

// telegramCoreAddresses 是 Telegram 核心网公开地址(与官方 tdesktop mtproto_dc_options.cpp 一致)。
// 服务端据握手帧里的 DC 索引选址;可用 config 的 dc-map 覆盖(测试/自建中继场景)。
var telegramCoreAddresses = map[int]string{
	1:   "149.154.175.50:443",
	2:   "149.154.167.51:443",
	3:   "149.154.175.100:443",
	4:   "149.154.167.91:443",
	5:   "149.154.171.5:443",
	203: "91.105.192.100:443",
}

// Config 是 MTProto 配置。
type Config struct {
	Secret   string         // ee 格式:hex 或 base64.RawURL,= 0xEE ‖ key[16] ‖ host(ASCII)
	DC       int            // 客户端出站用的 DC 索引(默认 2)
	DCMap    map[int]string // 服务端 DC → 地址覆盖(可选)
	TimeSkew time.Duration  // faketls 时间戳容差(默认 90s)
}

// Proxy 是 MTProto 协议插件实例。
type Proxy struct {
	key      []byte // 16 字节 proxy secret
	host     string // faketls SNI / domain fronting 主机名
	dc       int
	dcMap    map[int]string
	timeSkew time.Duration
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	cfg := Config{
		Secret: n.Get("secret").Str(),
		DC:     defaultDC,
	}
	if v := n.Get("dc").Str(); v != "" {
		d, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("mtproto: dc 非法:%w", err)
		}
		cfg.DC = d
	}
	if v := n.Get("time-skew").Str(); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("mtproto: time-skew 非法:%w", err)
		}
		cfg.TimeSkew = d
	}
	// dc-map: "1=host:port,2=host:port"
	if v := n.Get("dc-map").Str(); v != "" {
		cfg.DCMap = map[int]string{}
		for _, kv := range strings.Split(v, ",") {
			k, addrStr, ok := strings.Cut(strings.TrimSpace(kv), "=")
			if !ok {
				return cfg, fmt.Errorf("mtproto: dc-map 项 %q 应为 dc=host:port", kv)
			}
			d, err := strconv.Atoi(strings.TrimSpace(k))
			if err != nil {
				return cfg, fmt.Errorf("mtproto: dc-map 索引 %q 非法", k)
			}
			cfg.DCMap[d] = strings.TrimSpace(addrStr)
		}
	}
	return cfg, nil
}

// Build 构造 Proxy 实例。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	key, host, err := parseSecret(cfg.Secret)
	if err != nil {
		return nil, err
	}
	dc := cfg.DC
	if dc == 0 {
		dc = defaultDC
	}
	skew := cfg.TimeSkew
	if skew <= 0 {
		skew = defaultTimeSkew
	}
	return &Proxy{key: key, host: host, dc: dc, dcMap: cfg.DCMap, timeSkew: skew}, nil
}

// parseSecret 解析 ee 格式 secret:0xEE ‖ key[16] ‖ host(ASCII,无长度前缀)。
// 文本编码先试 hex,再试 base64.RawURL(与 Telegram 客户端分享链接一致)。
func parseSecret(s string) ([]byte, string, error) {
	if s == "" {
		return nil, "", errors.New("mtproto: secret 为空")
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, "", errors.New("mtproto: secret 既非 hex 也非 base64url")
		}
	}
	if len(raw) < 2 {
		return nil, "", errors.New("mtproto: secret 过短")
	}
	if raw[0] != secretFakeTLSFirstByte {
		return nil, "", fmt.Errorf("mtproto: secret 首字节应为 0xee(faketls),得到 %#x", raw[0])
	}
	raw = raw[1:]
	if len(raw) < obfsSecretKeyLen {
		return nil, "", errors.New("mtproto: secret 长度不足(需 16 字节 key)")
	}
	host := string(raw[obfsSecretKeyLen:])
	if host == "" {
		return nil, "", errors.New("mtproto: secret 缺 host(domain fronting 主机名)")
	}
	return raw[:obfsSecretKeyLen], host, nil
}

// ServerHandshake 服务端:先 faketls 握手,再 obfuscated2 握手,按 DC 索引合成目标地址。
func (p *Proxy) ServerHandshake(_ context.Context, below link.Stream, _ proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	tc, err := p.serverFakeTLS(below)
	if err != nil {
		return nil, nil, err
	}
	obfs, dc, err := readObfuscatedHandshake(tc, p.key)
	if err != nil {
		return nil, nil, err
	}
	dst, err := p.dcAddr(dc)
	if err != nil {
		return nil, nil, err
	}
	return &protoStream{Stream: below, rw: obfs}, &proxy.Request{
		Dst:     dst,
		Network: endpoint.NetworkTCP,
	}, nil
}

// serverFakeTLS 读 ClientHello、校验 digest 与时间戳,回三段响应,返回记录层包装的流。
func (p *Proxy) serverFakeTLS(below link.Stream) (*tlsConn, error) {
	tc := newTLSConn(below, nil)
	info, err := parseClientHello(tc.br)
	if err != nil {
		return nil, err
	}
	if err := verifyClientHello(info, p.key, p.timeSkew); err != nil {
		return nil, err
	}
	// SNI 必须等于 secret 里编码的 domain fronting 主机名(与真实现一致,防错配/探测)。
	if info.sni != p.host {
		return nil, fmt.Errorf("mtproto/faketls: SNI %q 与配置 host %q 不符", info.sni, p.host)
	}
	pkt, err := buildServerHello(info, p.key)
	if err != nil {
		return nil, err
	}
	if _, err := below.Write(pkt); err != nil {
		return nil, err
	}
	return tc, nil
}

// dcAddr 把 DC 索引解析成目标地址:优先 dc-map 覆盖,否则用内置公开表。
func (p *Proxy) dcAddr(dc int) (addr.Socksaddr, error) {
	s, ok := p.dcMap[dc]
	if !ok {
		s, ok = telegramCoreAddresses[dc]
	}
	if !ok {
		s = telegramCoreAddresses[defaultDC] // 未知 DC 回落默认
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return addr.Socksaddr{}, fmt.Errorf("mtproto: DC %d 地址 %q 非法:%w", dc, s, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return addr.Socksaddr{}, err
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		return addr.FromIPPort(netip.AddrPortFrom(ip, uint16(port))), nil
	}
	return addr.FromFqdn(host, uint16(port)), nil
}

// ClientHandshake 客户端:faketls 握手 + obfuscated2 握手。
// ★ dst 参数被忽略 —— MTProto 线上只传 DC 索引,目标由服务端据此合成(协议语义,非缺陷)。
func (p *Proxy) ClientHandshake(_ context.Context, below link.Stream, _ []byte, _ addr.Socksaddr) (link.Stream, error) {
	hello, clientRandom, err := buildClientHello(p.key, p.host)
	if err != nil {
		return nil, err
	}
	if _, err := below.Write(hello); err != nil {
		return nil, err
	}
	tc := newTLSConn(below, nil)
	if err := readServerHello(tc.br, p.key, clientRandom); err != nil {
		return nil, err
	}
	obfs, err := sendObfuscatedHandshake(tc, p.key, p.dc)
	if err != nil {
		return nil, err
	}
	return &protoStream{Stream: below, rw: obfs}, nil
}

// protoStream 把 obfuscated2 之上的读写抬成 link.Stream:Read/Write 走协议栈,
// 地址/截止时间/关闭沿用底层 stream。
type protoStream struct {
	link.Stream
	rw *obfsConn
}

func (s *protoStream) Read(p []byte) (int, error)  { return s.rw.Read(p) }
func (s *protoStream) Write(p []byte) (int, error) { return s.rw.Write(p) }
func (s *protoStream) Unwrap() any                 { return s.Stream }
