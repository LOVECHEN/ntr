// Package service 是运行时组装层:把注册表里的协议插件(proxy.Server)接成
// endpoint.InboundHandler,再经协议无关的 relay + 出站解析把连接跑通。
//
// ★它只认 proxy.Server / endpoint.Outbound / link.Stream —— 不 import 任何具体协议、
// 不 switch 协议类型。协议由 cmd 经 registry.Lookup 按名取得后注入,核心/运行时零协议 diff。
package service

import (
	"bytes"
	"context"
	cryptotls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/relay"
	"github.com/LOVECHEN/ntr/core/transport"
	"github.com/LOVECHEN/ntr/meter"
)

// OutboundResolver 把逻辑目标解析到一个出站(分流的最小面;完整 route.Engine 后续接入)。
type OutboundResolver interface {
	Resolve(ctx context.Context, dst addr.Socksaddr) (endpoint.Outbound, error)
}

// ConnResolver 是【带源上下文】的可选路由接口:实现者可据 client 源地址反查发起进程(process 规则)。
// HandleStream 优先用之;未实现的解析器(如 StaticOutbound)自动退回 OutboundResolver.Resolve。
type ConnResolver interface {
	ResolveConn(ctx context.Context, dst addr.Socksaddr, src netip.AddrPort, network string) (endpoint.Outbound, error)
}

// resolveOut 优先走 ConnResolver(带 src,供 process 规则);否则退回纯 dst 的 Resolve。
func resolveOut(ctx context.Context, r OutboundResolver, dst addr.Socksaddr, src netip.AddrPort, network string) (endpoint.Outbound, error) {
	if cr, ok := r.(ConnResolver); ok {
		return cr.ResolveConn(ctx, dst, src, network)
	}
	return r.Resolve(ctx, dst)
}

// NewResolverOutbound 把 OutboundResolver 适配成 endpoint.Outbound:每次拨号按 dst 现查规则引擎
// 选出站再委托。供【持 endpoint.Outbound 而非 resolver】的入站(TUN/tproxy/redirect/tunnel/会话式)
// 也享规则分流 + fake-ip 反查 —— 这正是 fake-ip 主用例(TUN/tproxy 只见 IP 的流量按域名分流)所需。
func NewResolverOutbound(r OutboundResolver) endpoint.Outbound { return resolverOutbound{r: r} }

type resolverOutbound struct{ r OutboundResolver }

var _ endpoint.Outbound = resolverOutbound{}

func (o resolverOutbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	out, err := resolveOut(ctx, o.r, dst, netip.AddrPort{}, "tcp")
	if err != nil {
		return nil, err
	}
	return out.DialStream(ctx, dst)
}

func (o resolverOutbound) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	out, err := resolveOut(ctx, o.r, dst, netip.AddrPort{}, "udp")
	if err != nil {
		return nil, err
	}
	return out.DialPacket(ctx, dst)
}

// srcAddrPort 取 client 连接的源地址(process 规则据此反查发起进程);取不到返回零值。
func srcAddrPort(s link.Stream) netip.AddrPort {
	if ra := s.RemoteAddr(); ra != nil {
		if ap, err := netip.ParseAddrPort(ra.String()); err == nil {
			return ap
		}
	}
	return netip.AddrPort{}
}

// StaticOutbound 恒返回同一个出站(单出站部署 / 测试用)。
type StaticOutbound struct{ Out endpoint.Outbound }

// Resolve 实现 OutboundResolver。
func (s StaticOutbound) Resolve(context.Context, addr.Socksaddr) (endpoint.Outbound, error) {
	if s.Out == nil {
		return nil, errors.New("service: StaticOutbound has nil Out")
	}
	return s.Out, nil
}

// ProxyInbound 把一条编译好的服务端栈抬成 endpoint.InboundHandler:
// Below 是【底→顶】排好序的传输层链(如 [tls]),顶上是 Proxy(终端协议)。
type ProxyInbound struct {
	Below []transport.StreamTransport // 底→顶;nil = 裸 TCP 直接跑协议
	Proxy proxy.Server
	Auth  proxy.Authenticator
	Out   OutboundResolver
	Meter *meter.Registry // 非 nil = 开启按用户计量(承 §5);nil = 关闭、零成本
	Gates []*meter.Gate   // 全局 + 每口连接闸/限速(承 §6.2 层1/2;可空)
	Sniff bool            // 开启域名嗅探:IP 目标 peek 首包 SNI/Host 解真域名再分流(承 §10.4.2)
	// Fallback:回落伪装站目标 host:port(非空才开)。协议握手失败(错凭据/畸形/非协议探测)时,不 RST/报错,
	// 而是把【握手已消费的原始字节 + 后续流】中继到该真站 —— 主动探测/直连浏览器只看到一个正常网站(抗探测)。
	// 禁改协议线格式:回落只是握手失败后的行为,不碰任何协议帧。发生在传输层(如 TLS)之上,故 dest 收到的是
	// 解密后的明文原始字节(与 xray/mihomo 的 fallback 同层)。仅在 Fallback≠"" 时才记录握手字节(否则零开销)。
	Fallback string // 单站回落(向后兼容;等价 Fallbacks=[{Dest:Fallback}])
	// Fallbacks:多站回落规则(按协商 ALPN + HTTP 请求 path 前缀选伪装站,对齐 xray fallbacks)。非空则优先。
	// 匹配:首条 (ALPN 空或命中协商 ALPN) 且 (Path 空或请求首行 path 以其为前缀) 的规则;无命中则关连接。
	Fallbacks []FallbackRule
}

// FallbackRule 是一条回落规则(对齐 xray fallbacks 的 name/alpn/path/dest/xver):SNI(空=任意,匹配 ClientHello
// ServerName)、ALPN(空=任意)、Path(空=任意;非空=HTTP 请求首行 path 前缀)、Dest(伪装站)、Xver(0=不发、
// 1=PROXY protocol v1、2=v2:向伪装站先发 PROXY 头带真实 src/dst,供其拿到真实客户端 IP)。三维皆空=兜底。
type FallbackRule struct {
	SNI  []string
	ALPN []string
	Path string
	Dest string
	Xver int
}

// fallbackRules 归一化:Fallbacks 优先;否则 Fallback 非空 → 一条无条件规则。
func (h *ProxyInbound) fallbackRules() []FallbackRule {
	if len(h.Fallbacks) > 0 {
		return h.Fallbacks
	}
	if h.Fallback != "" {
		return []FallbackRule{{Dest: h.Fallback}}
	}
	return nil
}

// hasFallback 报告是否配了回落(决定握手前是否录制)。
func (h *ProxyInbound) hasFallback() bool { return h.Fallback != "" || len(h.Fallbacks) > 0 }

// errFallback 是回落信号:携带录制流(含握手已消费字节 buf + 可取 ALPN 的底层 TLS)。
type errFallback struct{ rec *recordStream }

func (errFallback) Error() string { return "service: fallback to decoy" }

// recordStream 在回落开启时包住给协议握手的流:把握手读走的字节录进 buf,失败时回放给伪装站。
type recordStream struct {
	link.Stream
	buf bytes.Buffer
}

func (r *recordStream) Read(p []byte) (int, error) {
	n, err := r.Stream.Read(p)
	if n > 0 {
		r.buf.Write(p[:n])
	}
	return n, err
}

// replay 合成回放流:读 = 已录字节 ++ 底层后续;写/关 = 底层(握手期未写过客户端,下行干净)。
func (r *recordStream) replay() link.Stream {
	return &prefixStream{Stream: r.Stream, r: io.MultiReader(bytes.NewReader(r.buf.Bytes()), r.Stream)}
}

type prefixStream struct {
	link.Stream
	r io.Reader
}

func (p *prefixStream) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p *prefixStream) Unwrap() any                { return p.Stream }

// doFallback 按 ALPN + HTTP path 选伪装站,把握手失败的连接(回放已消费字节 + 后续)双向中继过去。
// dest 直连(net.Dial),不走出站/路由链(伪装站通常本地/内网)。无匹配规则 → 关连接(等价未配回落)。
//
// ★ALPN 从下层 TLS 取(可靠);path 从【握手已消费字节】best-effort 解(非阻塞,不多读避免与探测方"你先发我先发"
// 死锁)—— 对短 path 的 HTTP 探测足够(请求首行通常已在录制字节内)。故 ALPN 是主判据,path 为辅。
func (h *ProxyInbound) doFallback(ctx context.Context, rec *recordStream) error {
	sni, alpn := "", ""
	if c, ok := link.GetCapability[link.TLSConnCarrier](rec.Stream); ok {
		if tc, ok := c.TLSConn().(*cryptotls.Conn); ok {
			st := tc.ConnectionState()
			sni, alpn = st.ServerName, st.NegotiatedProtocol
		}
	}
	path := httpRequestPath(rec.buf.Bytes())
	dest, xver := h.selectFallback(sni, alpn, path)
	replay := rec.replay()
	if dest == "" {
		_ = replay.Close()
		return nil
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		_ = replay.Close()
		return err
	}
	// xver:向伪装站先发 PROXY protocol 头(带真实客户端/服务端地址),供其记真实来源 IP。
	if xver > 0 {
		if hdr := proxyProtocolHeader(xver, rec.Stream.RemoteAddr(), rec.Stream.LocalAddr()); hdr != nil {
			if _, err := conn.Write(hdr); err != nil {
				_ = conn.Close()
				_ = replay.Close()
				return err
			}
		}
	}
	return relay.Relay(connStream{conn}, replay)
}

// proxyProtocolHeader 编 PROXY protocol 头(v1 文本 / v2 二进制,haproxy 规范),把真实 src/dst 传给伪装站。
// 非 TCP 地址返回 nil(不发)。
func proxyProtocolHeader(v int, src, dst net.Addr) []byte {
	st, _ := src.(*net.TCPAddr)
	dt, _ := dst.(*net.TCPAddr)
	if st == nil || dt == nil {
		return nil
	}
	is4 := st.IP.To4() != nil && dt.IP.To4() != nil
	if v == 1 {
		proto := "TCP4"
		if !is4 {
			proto = "TCP6"
		}
		return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", proto, st.IP, dt.IP, st.Port, dt.Port))
	}
	// v2:12B 签名 + verCmd(0x21=v2/PROXY) + fam/proto + 2B 地址区长 + 地址区
	hdr := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21}
	var addrs []byte
	put16 := func(p int) { addrs = append(addrs, byte(p>>8), byte(p)) }
	if is4 {
		hdr = append(hdr, 0x11) // AF_INET + STREAM
		addrs = append(addrs, st.IP.To4()...)
		addrs = append(addrs, dt.IP.To4()...)
	} else {
		hdr = append(hdr, 0x21) // AF_INET6 + STREAM
		addrs = append(addrs, st.IP.To16()...)
		addrs = append(addrs, dt.IP.To16()...)
	}
	put16(st.Port)
	put16(dt.Port)
	hdr = append(hdr, byte(len(addrs)>>8), byte(len(addrs)))
	return append(hdr, addrs...)
}

// selectFallback 按 (SNI, ALPN, path) 选规则,返回 (dest, xver):首条 (SNI 空或命中) 且 (ALPN 空或命中) 且
// (Path 空或 path 以其为前缀) 的规则;无命中 dest 为空(→ 关连接)。
func (h *ProxyInbound) selectFallback(sni, alpn, path string) (string, int) {
	for _, r := range h.fallbackRules() {
		if (len(r.SNI) == 0 || sliceContains(r.SNI, sni)) &&
			(len(r.ALPN) == 0 || sliceContains(r.ALPN, alpn)) &&
			(r.Path == "" || strings.HasPrefix(path, r.Path)) {
			return r.Dest, r.Xver
		}
	}
	return "", 0
}

// httpRequestPath 从 HTTP 请求首行("METHOD SP path SP HTTP/x")解出 path;非 HTTP 返回空。
func httpRequestPath(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	f := bytes.Fields(b)
	if len(f) < 3 || !bytes.HasPrefix(f[2], []byte("HTTP/")) {
		return ""
	}
	return string(f[1])
}

func sliceContains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

var _ endpoint.InboundHandler = (*ProxyInbound)(nil)

// errAdmissionRejected:接入被拒 —— 凭据 Disable(§6.5)或触顶(max-conns/max-ips,§6.3)。
var errAdmissionRejected = errors.New("service: 接入被拒(停用 / 限额触顶)")

// Handshake 自底向上过传输层(ServerWrap)→ 跑协议握手(解出 dst + 归属凭据)→ 追认到
// Metadata,返回握手后的 stream + Request,【不做 relay】。供需要接管握手后 stream 的上层复用
// (如 reverse.Portal:控制连接要把 stream 当 mux 隧道,而非中继)。全程只认接口,不看协议。
func (h *ProxyInbound) Handshake(ctx context.Context, s link.Stream, md *endpoint.Metadata) (link.Stream, *proxy.Request, error) {
	below := s
	for _, t := range h.Below { // 底→顶:裸 TCP →(tls)→ 给协议的 stream
		wrapped, err := t.ServerWrap(ctx, below)
		if err != nil {
			_ = below.Close() // 传输层握手失败:关下层免泄漏(Close 幂等)
			return nil, nil, err
		}
		below = wrapped
	}
	// 回落开启:用 recordStream 录下握手读走的字节,失败时可原样回放给伪装站。
	hsInput := below
	var rec *recordStream
	if h.hasFallback() {
		rec = &recordStream{Stream: below}
		hsInput = rec
	}
	hs, req, err := h.Proxy.ServerHandshake(ctx, hsInput, h.Auth)
	if err != nil {
		if rec != nil {
			// 握手失败但配了回落:不关流,交 HandleStream 按 ALPN/path 选伪装站中继(回放已消费字节 + 后续)。
			return nil, nil, errFallback{rec: rec}
		}
		// 协议握手失败(错凭据/畸形/探测常态):关已包裹的 below,触发传输层收尾——
		// 如 grpc 的 grpcConn.Close→close(gc.done),放行否则永久阻塞在 <-gc.done 的 handler goroutine。
		_ = below.Close()
		return nil, nil, err
	}
	md.BindCred(req.Cred)    // 鉴权完成那刻追认归属
	md.Destination = req.Dst // 代理协议的目标在握手后才可知
	return hs, req, nil
}

// streamDispatcher 实现 proxy.StreamDispatcher:把一条已解密的 mux 子流按其真实目标解析出站 →
// 拨 → 接入闸 + 按 who 计量 → 双向中继。供 vmess 等"库内解复用"协议经 ctx 调用(每子流一 goroutine,
// 见 vmess server.go)。承载对核心不可见,故一子流 = 一连接(max-conns 按子流计),字节记到 who。
type streamDispatcher struct {
	h   *ProxyInbound
	src addr.Socksaddr // 承载连接的对端(max-ips 键)
}

func (d streamDispatcher) DispatchStream(ctx context.Context, conn net.Conn, dst addr.Socksaddr, who cred.Ref) {
	out, err := d.h.Out.Resolve(ctx, dst)
	if err != nil {
		_ = conn.Close()
		return
	}
	up, err := out.DialStream(ctx, dst)
	if err != nil {
		_ = conn.Close()
		return
	}
	s, release, err := d.h.admit(who.ID, d.src, connStream{conn}, connStream{conn}, up)
	if err != nil {
		return // admit 已关两端
	}
	defer release()
	_ = relay.Relay(s, up)
}

// HandleStream:握手 → 解析出站 → 拨 → 双向中继。全程不看协议/传输是什么,只认接口。
func (h *ProxyInbound) HandleStream(ctx context.Context, s link.Stream, md *endpoint.Metadata) error {
	// 注入 mux 子流中继器:供【传输库内部自解复用 mux】的协议(vmess)把每条子流交回核心中继
	// (它够不到出站解析器,故经 ctx 递数据式能力;其余协议忽略)。见 core/proxy/dispatcher.go。
	ctx = proxy.WithStreamDispatcher(ctx, streamDispatcher{h: h, src: md.Source})
	hs, req, err := h.Handshake(ctx, s, md)
	if err != nil {
		var fb errFallback
		if errors.As(err, &fb) {
			return h.doFallback(ctx, fb.rec) // 握手失败 → 按 ALPN/path 选伪装站中继(抗探测)
		}
		if errors.Is(err, proxy.ErrHandled) {
			return nil // 协议已在内部把整条连接(所有 mux 子流)接入 + 计量 + 中继完毕(经 streamDispatcher)
		}
		return err
	}

	// mux 承载连接(握手目标 == sing-mux 魔术域名 / Xray 的 v1.mux.cool:9527)→ 先按【整条承载】过接入闸 +
	// 计量(所有子流的字节含 mux 帧头都记到该用户,计 1 连接),再交解复用(其上多条子流各按真实目标落地)。
	// 协议无关:任何入站(vless/trojan/ss…)只要解出该目标即为载体,与 sing-box/mihomo/Xray 互通。
	if req.Network == endpoint.NetworkTCP && (isMuxCarrier(req.Dst) || isMuxCoolCarrier(req.Dst)) {
		carrier, release, err := h.admit(req.Cred.ID, md.Source, hs, hs)
		if err != nil {
			return err
		}
		defer release()
		if isMuxCarrier(req.Dst) {
			return handleMuxCarrier(ctx, carrier, h.Out)
		}
		return handleMuxCoolCarrier(ctx, carrier, h.Out)
	}

	if req.Network == endpoint.NetworkUDP { // 归一化网络判 UDP,不看协议私有 Command
		return h.relayPacket(ctx, hs, req, md)
	}

	// 域名嗅探:目标只是 IP 时,peek 首包从 SNI/Host 解出真域名 → 覆盖路由目标(命中 domain/geosite/rule-set);
	// replay 流保住已读的首包字节交给下游 relay,零丢失。已带域名的目标不嗅(省一次 peek)。
	if h.Sniff && req.Dst.IsIP() {
		proto, domain, replay, fail := sniff(hs, sniffTimeout)
		md.SetSniff(proto, domain, fail)
		hs = replay
		if domain != "" {
			req.Dst = addr.FromFqdn(domain, req.Dst.Port)
		}
	}

	// process 规则:用最外层 client 连接的源地址(s,非 sniff 包装后的 hs)反查发起进程。
	out, err := resolveOut(ctx, h.Out, req.Dst, srcAddrPort(s), "tcp")
	if err != nil {
		_ = hs.Close()
		return err
	}
	up, err := out.DialStream(ctx, req.Dst)
	if err != nil {
		_ = hs.Close()
		return err
	}
	hs, release, err := h.admit(req.Cred.ID, md.Source, hs, hs, up)
	if err != nil {
		return err
	}
	defer release()
	return relay.Relay(hs, up) // Relay 内部负责两端收尾
}

// admitConn 是接入的唯一入口(所有落地路径 —— 普通 TCP、UDP-over-stream、mux 承载、库内 mux 子流 ——
// 都经此,不许绕):
//  1. 全局 / 每口连接闸(§6.2 层1/2,max-conns):接入 CAS,叠加顺序 全局→口,任一超即拒;
//  2. 按用户计量 + 热开关 + 每用户限额(开启时):登记到 who 的 Cell(kill=关 closers);Disable(§6.5)/
//     触顶(max-conns/max-ips,§6.3)→ 拒新、立即关。
//
// 返回本连接的计量器(nil = 计量关闭且无闸,零成本)+ release(调用方 defer:注销连接 + 放闸)。
// 被拒返回 errAdmissionRejected,closers 已关。
func (h *ProxyInbound) admitConn(who cred.ID, src addr.Socksaddr, closers ...interface{ Close() error }) (*meter.Meter, func(), error) {
	closeAll := func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}
	for i, g := range h.Gates {
		if !g.TryAcquire() {
			for _, gg := range h.Gates[:i] {
				gg.Release()
			}
			closeAll()
			return nil, nil, errAdmissionRejected
		}
	}
	releaseGates := func() {
		for _, g := range h.Gates {
			g.Release()
		}
	}
	if h.Meter != nil {
		mm, done, ok := h.Meter.Open(who, src.Addr, closeAll)
		if !ok {
			releaseGates()
			closeAll()
			return nil, nil, errAdmissionRejected
		}
		return mm.WithGates(h.Gates), func() { done(); releaseGates() }, nil
	}
	if len(h.Gates) > 0 {
		return meter.GateMeter(h.Gates), releaseGates, nil // 仅全局/每口限速(未开按用户计量)
	}
	return nil, func() {}, nil
}

// admit = admitConn + 包客户端侧流 s(Read=上行、Write=下行,稀疏累计到 who;gate 的 rate 也在稀疏点一并
// throttle)。返回包好的流 + release。
func (h *ProxyInbound) admit(who cred.ID, src addr.Socksaddr, s link.Stream, closers ...interface{ Close() error }) (link.Stream, func(), error) {
	m, release, err := h.admitConn(who, src, closers...)
	if err != nil {
		return nil, nil, err
	}
	if m != nil {
		s = meter.Wrap(s, m)
	}
	return s, release, nil
}

// relayPacket 走 UDP 路径:靠能力发现把握手后的 stream 适配成 PacketConn(★先适配再计量:各协议的
// ServerPacketConn 要对 hs 做本协议类型断言,不能先包 meter),接入闸 + 按用户计量(datagram 级:
// ReadPacket=上行、WritePacket=下行),拨 UDP 出站,双向搬 datagram。协议不支持 UDP-over-stream(无
// PacketConnServer 能力)则大声报。
func (h *ProxyInbound) relayPacket(ctx context.Context, hs link.Stream, req *proxy.Request, md *endpoint.Metadata) error {
	pcs, ok := h.Proxy.(proxy.PacketConnServer)
	if !ok {
		_ = hs.Close()
		return fmt.Errorf("service: 协议不支持 UDP-over-stream(无 PacketConnServer 能力)")
	}
	clientPC, err := pcs.ServerPacketConn(hs, req.Dst)
	if err != nil {
		_ = hs.Close()
		return err
	}
	m, release, err := h.admitConn(req.Cred.ID, md.Source, clientPC)
	if err != nil {
		return err // admitConn 已关 clientPC(其 Close 收尾 hs)
	}
	defer release()
	defer clientPC.Close()
	if m != nil {
		clientPC = meter.WrapPacket(clientPC, m)
	}
	// udpNAT 按 per-packet dst 分发到多条单目标出站:单目标协议(VLESS)退化为 1 条,多目标
	// (Trojan,每包自带地址)则每目标 1 条。取代原来的单条 DialPacket(req.Dst)+RelayPacket。
	return udpNAT(ctx, clientPC, h.Out)
}

// ServerPacketConn 把 UDP 握手后的 stream 经协议的 PacketConnServer 能力适配成用户侧
// link.PacketConn(多目标)。供 reverse.Portal 复用:UDP 用户流不 relay 到 direct 出站,
// 而是桥到反连隧道。协议无 UDP-over-stream 能力则大声报。
func (h *ProxyInbound) ServerPacketConn(hs link.Stream, dst addr.Socksaddr) (link.PacketConn, error) {
	pcs, ok := h.Proxy.(proxy.PacketConnServer)
	if !ok {
		return nil, fmt.Errorf("service: 协议不支持 UDP-over-stream(无 PacketConnServer 能力)")
	}
	return pcs.ServerPacketConn(hs, dst)
}

// HandlePacket:入站已是 PacketConn 形状(TUN/SOCKS-UDP)的处理待 udpnat 落地,大声报不静默。
func (h *ProxyInbound) HandlePacket(context.Context, link.PacketConn, *endpoint.Metadata) error {
	return errors.New("service: native PacketConn inbound not implemented yet (pending udpnat)")
}
