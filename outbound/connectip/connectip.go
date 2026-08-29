//go:build with_connectip

// Package connectip 的出站实现:RFC 9484 CONNECT-IP(L3 over HTTP/3)。
//
// ★ build tag 隔离(-tags with_connectip):它需要用户态 netstack 把 L3 IP 包合成 L4 连接,
// 依赖 golang.zx2c4.com/wireguard/tun/netstack(内含 gVisor),与瘦核心默认形态冲突。
// capsule.go / datagram.go 是纯编解码、零依赖,不在 tag 之后。
//
// 链路:
//
//	DialStream(dst) → netstack.Net.DialContext → 合成完整 IP 包 → tun.Device
//	  → 泵 → HTTP Datagram(Context ID 0 + 完整 IP 包)→ h3 请求流 → 代理
//
// ★ 同一套实现覆盖标准版与 Cloudflare 变体(NTR 是插件系统,差异做成配置而非分叉代码):
//   - protocol:        标准 "connect-ip";Cloudflare 用 "cf-connect-ip"
//   - extra-settings:  Cloudflare 要求发已废弃的 SETTINGS_H3_DATAGRAM_00 (0x276)
//   - ignore-extended-connect: Cloudflare 不发 SETTINGS_ENABLE_CONNECT_PROTOCOL,需跳过该校验
//
// 这三处是握手层标识差异,协议主体(capsule / datagram / IP 包封装)两者一致。
package connectip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	mhttp "github.com/metacubex/http"
	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	mtls "github.com/metacubex/tls"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = (*Outbound)(nil)

const (
	// protocolStandard 是 RFC 9484 §4 规定的升级令牌 / :protocol 值。
	protocolStandard = "connect-ip"
	// defaultTemplate 是 RFC 9484 §3 的默认 URI 模板(target/ipproto 均通配 = 全隧道)。
	defaultTemplate = "/.well-known/masque/ip/*/*/"
	defaultMTU      = 1400
)

// Options 是 CONNECT-IP 出站配置。
type Options struct {
	Server   string // 代理 host:port(QUIC/UDP)
	SNI      string
	Insecure bool

	Protocol              string            // :protocol 值(默认 connect-ip;Cloudflare: cf-connect-ip)
	URITemplate           string            // 默认 /.well-known/masque/ip/*/*/
	ExtraSettings         map[uint64]uint64 // 额外 h3 SETTINGS(Cloudflare 需 {0x276: 1})
	IgnoreExtendedConnect bool              // 跳过服务端 Extended CONNECT 能力校验(Cloudflare 需)

	LocalAddress []string // 隧道内本端地址(CIDR 或裸 IP)
	DNS          []string
	MTU          int

	ClientCert string // 可选 mTLS(Cloudflare Access 用)证书 PEM
	ClientKey  string
}

// Outbound 是 CONNECT-IP 出站:一条 h3 请求流承载整条 L3 隧道,内侧接 netstack。
type Outbound struct {
	tnet   *netstack.Net
	rs     *http3.RequestStream
	tunDev wgtun.Device
	pc     net.PacketConn
	qc     *quic.Conn
	cancel context.CancelFunc
	once   sync.Once
}

// NewOutbound 建 QUIC+h3 连接、发起 CONNECT-IP、起 netstack 与双向泵。
func NewOutbound(o Options) (*Outbound, error) {
	locals, err := parseAddrs(o.LocalAddress)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: local-address:%w", err)
	}
	if len(locals) == 0 {
		return nil, errors.New("connect-ip: 需至少一个 local-address(隧道内本端 IP)")
	}
	dns, err := parseAddrs(o.DNS)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: dns:%w", err)
	}
	mtu := o.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	tlsConf := &mtls.Config{
		ServerName:         o.SNI,
		InsecureSkipVerify: o.Insecure,
		NextProtos:         []string{http3.NextProtoH3},
	}
	if o.ClientCert != "" && o.ClientKey != "" { // mTLS(Cloudflare Access)
		cert, err := mtls.X509KeyPair([]byte(o.ClientCert), []byte(o.ClientKey))
		if err != nil {
			return nil, fmt.Errorf("connect-ip: 客户端证书:%w", err)
		}
		tlsConf.Certificates = []mtls.Certificate{cert}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", o.Server)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	qc, err := quic.Dial(context.Background(), pc, udpAddr,
		tlsConf, &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}

	tr := &http3.Transport{EnableDatagrams: true, AdditionalSettings: o.ExtraSettings}
	cc := tr.NewClientConn(qc)

	ctx, cancel := context.WithCancel(context.Background())
	fail := func(e error) (*Outbound, error) {
		cancel()
		_ = qc.CloseWithError(0, "")
		_ = pc.Close()
		return nil, e
	}

	// 等 SETTINGS,并按配置决定是否强制要求 Extended CONNECT。
	select {
	case <-cc.ReceivedSettings():
	case <-qc.Context().Done():
		return fail(qc.Context().Err())
	}
	st := cc.Settings()
	if !o.IgnoreExtendedConnect && !st.EnableExtendedConnect {
		return fail(errors.New("connect-ip: 服务端未启用 Extended CONNECT(Cloudflare 端可设 ignore-extended-connect)"))
	}
	if !st.EnableDatagrams {
		return fail(errors.New("connect-ip: 服务端未启用 HTTP Datagram"))
	}

	rs, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return fail(err)
	}
	if err := rs.SendRequestHeader(buildRequest(o)); err != nil {
		return fail(err)
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		return fail(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 { // RFC 9484 §4.5:2xx 即成功
		return fail(fmt.Errorf("connect-ip: 服务端响应 %d(期望 2xx)", resp.StatusCode))
	}

	tunDev, tnet, err := netstack.CreateNetTUN(locals, dns, mtu)
	if err != nil {
		return fail(fmt.Errorf("connect-ip: 建用户态 netstack 失败:%w", err))
	}

	out := &Outbound{tnet: tnet, rs: rs, tunDev: tunDev, pc: pc, qc: qc, cancel: cancel}
	go out.pumpOutbound(mtu)
	go out.pumpInbound(ctx)
	return out, nil
}

// buildRequest 造 Extended CONNECT 请求。★ :protocol 靠 http.Request.Proto 表达,
// 必须手搓 Request —— http.NewRequest 会把 Proto 置成 "HTTP/1.1" 从而退化成普通 CONNECT。
func buildRequest(o Options) *mhttp.Request {
	proto := o.Protocol
	if proto == "" {
		proto = protocolStandard
	}
	tmpl := o.URITemplate
	if tmpl == "" {
		tmpl = defaultTemplate
	}
	hdr := mhttp.Header{
		"Capsule-Protocol": []string{"?1"}, // RFC 9297 §3.4
	}
	return &mhttp.Request{
		Method: mhttp.MethodConnect,
		Proto:  proto, // → :protocol
		URL:    &neturl.URL{Scheme: "https", Host: o.Server, Path: tmpl},
		Host:   o.Server,
		Header: hdr,
	}
}

// pumpOutbound:netstack 出站 IP 包 → HTTP Datagram(Context ID 0 + 完整 IP 包)。
func (o *Outbound) pumpOutbound(mtu int) {
	bufs := [][]byte{make([]byte, mtu+80)} // 留 netstack 可能的 offset 余量
	sizes := make([]int, 1)
	for {
		n, err := o.tunDev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := range n {
			if sizes[i] <= 0 {
				continue
			}
			if err := o.rs.SendDatagram(prependContextID(bufs[i][:sizes[i]])); err != nil {
				return
			}
		}
	}
}

// pumpInbound:HTTP Datagram → 剥 Context ID → 完整 IP 包注入 netstack。
func (o *Outbound) pumpInbound(ctx context.Context) {
	for {
		data, err := o.rs.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		pkt, ok := stripContextID(data)
		if !ok || len(pkt) == 0 {
			continue // 非零 Context ID / 空包:按 RFC 丢弃
		}
		if _, err := o.tunDev.Write([][]byte{pkt}, 0); err != nil {
			return
		}
	}
}

// DialStream 经隧道内 netstack 拨 TCP。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	c, err := o.tnet.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, err
	}
	return connStream{c}, nil
}

// DialPacket 经隧道内 netstack 拨 UDP(单目标)。
func (o *Outbound) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	c, err := o.tnet.DialContext(ctx, "udp", dst.String())
	if err != nil {
		return nil, err
	}
	return &udpConn{Conn: c, dst: dst}, nil
}

// Close 收尾(幂等)。
func (o *Outbound) Close() error {
	o.once.Do(func() {
		o.cancel()
		_ = o.rs.Close()
		_ = o.tunDev.Close()
		_ = o.qc.CloseWithError(0, "")
		_ = o.pc.Close()
	})
	return nil
}

// parseAddrs 解析地址列表,接受裸 IP 或 CIDR(取地址部分)。
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

type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

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
