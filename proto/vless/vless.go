package vless

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/muxcool"
)

// 编译期断言:VLESS 作为纯插件实现统一的 proxy.Server / proxy.Client 契约,
// 并声明自己的凭据编解码(UUID)。
var (
	_ proxy.Server          = (*Proxy)(nil)
	_ proxy.Client          = (*Proxy)(nil)
	_ proxy.CredentialCodec = (*Proxy)(nil)
)

// Config 是 VLESS 协议自有配置(per-口)。per-user 的 UUID 是凭据(keys.vless),
// 在 admission 期由 Authenticator 匹配,不在此。
type Config struct {
	Flow string // 空 = 无 flow;"xtls-rprx-vision" 需 vision addon(尚未实现,握手时大声报)
}

// Parse 从哑配置节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	return Config{Flow: n.Get("flow").Str()}, nil
}

// Proxy 是 VLESS 的连接级句柄(Descriptor.Build 产物)。VLESS 无状态,握手只写/读一次头。
type Proxy struct {
	cfg Config
}

// Build 构造 Proxy(承 registry.Descriptor.Build)。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	return &Proxy{cfg: cfg}, nil
}

// ClientKey / AuthKey 实现 proxy.CredentialCodec:VLESS 凭据 = 16 字节 UUID,
// 客户端出示与服务端登记同源(都由 hex UUID 解析)。
func (*Proxy) ClientKey(secret string) ([]byte, error) { return parseUUID(secret) }
func (*Proxy) AuthKey(secret string) ([]byte, error)   { return parseUUID(secret) }

// parseUUID 把 hex UUID(可带连字符)解成 16 字节。
func parseUUID(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil {
		return nil, err
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("vless: UUID 应为 16 字节,得到 %d", len(b))
	}
	return b, nil
}

// ServerHandshake 实现 proxy.Server:读 VLESS 请求头,经 auth 解析 UUID→凭据,返回承载
// payload 的 stream(首次写自动前置响应头)+ Request。
func (p *Proxy) ServerHandshake(_ context.Context, below link.Stream, auth proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	h, err := readRequestHeader(below)
	if err != nil {
		return nil, nil, err
	}
	ref, ok := auth.Auth("vless", h.UUID[:])
	if !ok {
		// 绝不静默:未知 UUID 大声报(承 §1.5 绝不静默)。
		return nil, nil, fmt.Errorf("vless: unknown user id %x", h.UUID)
	}
	// Mux.cool 载体:命令 Mux(线上不带地址)→ 翻译成规范魔术目标,交运行时按地址识别载体
	// (与 sing-mux / trojan-ss 的地址式识别统一,核心保持协议无关)。
	if h.Command == CmdMux {
		h.Dst = addr.FromFqdn(muxcool.CarrierFqdn, muxcool.CarrierPort)
	}
	net := endpoint.NetworkTCP
	if h.Command == CmdUDP {
		net = endpoint.NetworkUDP
	}
	// 客户端请求头里的 flow 决定线格式:vision → VisionConn 接管(padding/splice);否则普通 serverStream。
	if parseFlowAddon(h.Addons) == flowVision {
		if h.Command == CmdUDP {
			return nil, nil, fmt.Errorf("vless: %s flow 不支持 UDP", flowVision)
		}
		vs, err := serverVision(below, h.UUID)
		if err != nil {
			return nil, nil, err
		}
		return vs, &proxy.Request{Dst: h.Dst, Cred: ref, Network: net, Command: h.Command}, nil
	}
	return &serverStream{Stream: below}, &proxy.Request{Dst: h.Dst, Cred: ref, Network: net, Command: h.Command}, nil
}

// ClientHandshake 实现 proxy.Client:写 VLESS 请求头(出示 key=UUID),返回承载 payload 的
// stream(首次读自动 strip 响应头)。
func (p *Proxy) ClientHandshake(_ context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.Stream, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("vless: uuid key must be 16 bytes, got %d", len(key))
	}
	var uuid [16]byte
	copy(uuid[:], key)
	if p.cfg.Flow == flowVision {
		return clientVision(below, uuid, dst) // Vision:惰性头 + VisionConn 包裹
	}
	if p.cfg.Flow != "" {
		return nil, fmt.Errorf("vless: flow %q not supported(仅 %s)", p.cfg.Flow, flowVision)
	}
	// 目标为 Mux.cool 魔术载体 → 发 Command=Mux(线上不带地址,对齐 Xray 客户端);否则普通 TCP。
	cmd := CmdTCP
	if dst.IsFqdn() && dst.Fqdn == muxcool.CarrierFqdn && dst.Port == muxcool.CarrierPort {
		cmd = CmdMux
	}
	if err := writeRequestHeader(below, uuid, cmd, dst); err != nil {
		return nil, err
	}
	return &clientStream{Stream: below}, nil
}

// readRequestHeader 从 r 读一个 VLESS 请求头(服务端;r 剩余即 payload)。
func readRequestHeader(r io.Reader) (RequestHeader, error) {
	var h RequestHeader

	var fixed [18]byte // version(1) + uuid(16) + addonLen(1)
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return h, err
	}
	if fixed[0] != Version {
		return h, ErrVersion
	}
	copy(h.UUID[:], fixed[1:17])
	if alen := int(fixed[17]); alen > 0 {
		h.Addons = make([]byte, alen)
		if _, err := io.ReadFull(r, h.Addons); err != nil {
			return h, err
		}
	}
	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return h, err
	}
	h.Command = cmd[0]
	if h.Command == CmdTCP || h.Command == CmdUDP {
		d, err := readAddrPortStream(r)
		if err != nil {
			return h, err
		}
		h.Dst = d
	}
	return h, nil
}

// writeRequestHeader 写一个 VLESS 请求头到 w(客户端)。
func writeRequestHeader(w io.Writer, uuid [16]byte, cmd byte, dst addr.Socksaddr) error {
	b := buf.New()
	defer b.Release()
	if err := (RequestCodec{}).Encode(b, RequestHeader{UUID: uuid, Command: cmd, Dst: dst}); err != nil {
		return err
	}
	_, err := w.Write(b.Bytes())
	return err
}

func readAddrPortStream(r io.Reader) (addr.Socksaddr, error) {
	var d addr.Socksaddr
	var pa [3]byte // port(2 BE) + atyp(1)
	if _, err := io.ReadFull(r, pa[:]); err != nil {
		return d, err
	}
	port := binary.BigEndian.Uint16(pa[:2])
	switch pa[2] {
	case atypIPv4:
		var a4 [4]byte
		if _, err := io.ReadFull(r, a4[:]); err != nil {
			return d, err
		}
		return addr.FromIPPort(netip.AddrPortFrom(netip.AddrFrom4(a4), port)), nil
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return d, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return d, err
		}
		return addr.FromFqdn(string(name), port), nil
	case atypIPv6:
		var a16 [16]byte
		if _, err := io.ReadFull(r, a16[:]); err != nil {
			return d, err
		}
		return addr.FromIPPort(netip.AddrPortFrom(netip.AddrFrom16(a16), port)), nil
	default:
		return d, ErrAtyp
	}
}

// serverStream 是服务端 payload 流:首次写自动前置 VLESS 响应头(version + addonLen 0)。
type serverStream struct {
	link.Stream // 下层(below);Read/Close/addrs/deadlines 由它提供
	wroteResp   bool
}

func (s *serverStream) Write(p []byte) (int, error) {
	if s.wroteResp {
		return s.Stream.Write(p)
	}
	s.wroteResp = true
	b := buf.New()
	defer b.Release()
	if err := EncodeResponseHeader(b); err != nil {
		return 0, err
	}
	if _, err := b.Write(p); err != nil {
		return 0, err
	}
	if _, err := s.Stream.Write(b.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *serverStream) Unwrap() any { return s.Stream }

// clientStream 是客户端 payload 流:首次读自动 strip VLESS 响应头。
type clientStream struct {
	link.Stream
	strippedResp bool
}

func (c *clientStream) Read(p []byte) (int, error) {
	if !c.strippedResp {
		c.strippedResp = true
		var vh [2]byte // version(1) + addonLen(1)
		if _, err := io.ReadFull(c.Stream, vh[:]); err != nil {
			return 0, err
		}
		if vh[0] != Version {
			return 0, ErrVersion
		}
		if alen := int(vh[1]); alen > 0 {
			if _, err := io.ReadFull(c.Stream, make([]byte, alen)); err != nil {
				return 0, err
			}
		}
	}
	return c.Stream.Read(p)
}

func (c *clientStream) Unwrap() any { return c.Stream }
