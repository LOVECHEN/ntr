//go:build with_connectip

package connectip

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	mhttp "github.com/metacubex/http"
	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	mtls "github.com/metacubex/tls"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

// Inbound 是 CONNECT-IP 入站:在 UDP 上跑 QUIC + HTTP/3,接受 Extended CONNECT
// (:protocol = connect-ip 或 cf-connect-ip),接管请求流后把对端送来的完整 IP 包
// 经服务端侧 netstack 合成回 L4 连接、交给绑定的出站落地。
//
// 自管 UDP 监听(Run),不走 NTR 的 TCP 接入环。
type Inbound struct {
	tlsConfig *mtls.Config
	out       endpoint.Outbound
	srv       *http3.Server
	assignIP  netip.Prefix // 下发给对端的隧道内地址(ADDRESS_ASSIGN)
	mtu       uint32
	users     map[string]string // name→password(可选 Basic;空=开放隧道)
	hook      MeterHook         // 隧道级接入/计量(nil=不计量不设闸)
}

// InboundOptions 是 CONNECT-IP 入站配置。
type InboundOptions struct {
	AssignAddress string // 下发给客户端的隧道内地址(CIDR),如 10.9.0.2/32
	MTU           int
	ExtraSettings map[uint64]uint64 // 与客户端对齐用(如 Cloudflare 的 0x276)
}

// NewInbound 构造 CONNECT-IP 入站。users 非空 → 开启可选 HTTP Basic 鉴权;hook 非 nil → 隧道级接入+计量。
func NewInbound(o InboundOptions, users []User, hook MeterHook, tlsAny any, out endpoint.Outbound) (*Inbound, error) {
	tlsConfig, ok := tlsAny.(*mtls.Config)
	if !ok {
		return nil, errors.New("connect-ip: 需要 *metacubex/tls.Config")
	}
	um := make(map[string]string, len(users))
	for _, u := range users {
		if u.Name != "" {
			um[u.Name] = u.Password
		}
	}
	assign := netip.MustParsePrefix("10.9.0.2/32")
	if o.AssignAddress != "" {
		p, err := netip.ParsePrefix(o.AssignAddress)
		if err != nil {
			return nil, errors.New("connect-ip: assign-address 应为 CIDR")
		}
		assign = p
	}
	mtu := uint32(defaultMTU)
	if o.MTU > 0 {
		mtu = uint32(o.MTU)
	}
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	h := &Inbound{tlsConfig: tlsConfig, out: out, assignIP: assign, mtu: mtu, users: um, hook: hook}
	h.srv = &http3.Server{
		EnableDatagrams:    true,
		AdditionalSettings: o.ExtraSettings,
		Handler:            mhttp.HandlerFunc(h.serve),
	}
	return h, nil
}

// Run 绑定 UDP 监听并跑 QUIC + H3 服务端,阻塞至 ctx 取消。
func (h *Inbound) Run(ctx context.Context, listenAddr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer pc.Close()
	ln, err := quic.ListenEarly(pc, h.tlsConfig, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  30 * time.Second,
	})
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go func() { _ = h.srv.ServeQUICConn(conn) }()
	}
}

// HandlePacket:CONNECT-IP 无原生 PacketConn 入站形状。
func (h *Inbound) HandlePacket(context.Context, link.PacketConn, *endpoint.Metadata) error {
	return errors.New("connect-ip: packet inbound not supported")
}

// serve 处理一条 h3 请求:必须是 Extended CONNECT 且 :protocol 为 connect-ip 变体之一。
// ★ 同时接受标准值与 Cloudflare 值 —— 服务端宽容,便于与两类客户端互通。
func (h *Inbound) serve(w mhttp.ResponseWriter, r *mhttp.Request) {
	if r.Method != mhttp.MethodConnect {
		mhttp.Error(w, "method not allowed", mhttp.StatusMethodNotAllowed)
		return
	}
	if r.Proto != protocolStandard && r.Proto != "cf-connect-ip" {
		mhttp.Error(w, "unsupported :protocol", mhttp.StatusBadRequest)
		return
	}
	user, ok := h.authUser(r.Header.Get("Proxy-Authorization"))
	if !ok {
		mhttp.Error(w, "proxy auth required", mhttp.StatusProxyAuthRequired)
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		mhttp.Error(w, "no hijack", mhttp.StatusInternalServerError)
		return
	}
	ctx := r.Context()

	st, err := newIPStack(ctx, h.mtu, h.out)
	if err != nil {
		mhttp.Error(w, "stack init failed", mhttp.StatusInternalServerError)
		return
	}
	defer st.Close()

	w.Header().Set("Capsule-Protocol", "?1") // RFC 9297 §3.4
	w.WriteHeader(mhttp.StatusOK)            // RFC 9484 §4.5:2xx 即成功
	hs := streamer.HTTPStream()
	defer hs.Close()

	// 隧道级接入 + 计量(hook 非 nil):认证用户 → 连接闸 + max-ips + 按整条隧道记 IP 包字节。
	// closer=hs 交接入器,Disable/KillIP 时强杀本隧道。被拒(闸满/内存档)→ 关流退出。
	var addUp, addDown func(int)
	if h.hook != nil {
		up, down, release, admitOK := h.hook(ctx, user, remoteAddr(r.RemoteAddr), hs)
		if !admitOK {
			return
		}
		defer release()
		addUp, addDown = up, down
	}

	// 按 RFC 9484 §4.7 在流上下发 ADDRESS_ASSIGN + ROUTE_ADVERTISEMENT。
	// (客户端也可用本地配置的地址;这里下发是标准行为,便于与标准实现互通。)
	if capsules, err := h.initialCapsules(); err == nil {
		_, _ = hs.Write(capsules)
	}

	// 双向泵:datagram 载的是【完整 IP 包】(Context ID 0)。
	done := make(chan struct{}, 2)
	go func() { // 隧道 → 栈
		for {
			data, err := hs.ReceiveDatagram(ctx)
			if err != nil {
				done <- struct{}{}
				return
			}
			pkt, ok := stripContextID(data)
			if !ok {
				continue // 非零 Context ID:按 RFC 丢弃
			}
			if addUp != nil {
				addUp(len(pkt)) // 上行:客户端 → 出站,记整条隧道字节
			}
			st.Inject(pkt)
		}
	}()
	go func() { // 栈 → 隧道
		for {
			pkt, ok := st.ReadPacket(ctx)
			if !ok {
				done <- struct{}{}
				return
			}
			if addDown != nil {
				addDown(len(pkt)) // 下行:出站 → 客户端
			}
			if err := hs.SendDatagram(prependContextID(pkt)); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

// initialCapsules 拼出握手后下发的两条 capsule:分配地址 + 通告全网可路由。
func (h *Inbound) initialCapsules() ([]byte, error) {
	assign, err := EncodeAddressAssign([]AssignedAddress{
		{RequestID: 0, Prefix: h.assignIP}, // 非响应式下发,RequestID 为 0(§4.7.1)
	})
	if err != nil {
		return nil, err
	}
	routes, err := EncodeRouteAdvertisement([]IPRoute{
		{Start: netip.MustParseAddr("0.0.0.0"), End: netip.MustParseAddr("255.255.255.255"), IPProtocol: 0},
	})
	if err != nil {
		return nil, err
	}
	return append(assign, routes...), nil
}

// authUser:未配用户 = 不鉴权(返回 "",true → Ambient);配了则校验 "Basic base64(user:pass)",
// 成功返回命中的用户名(= 计费 BillID,与 refs 键一致)。
func (h *Inbound) authUser(header string) (string, bool) {
	if len(h.users) == 0 {
		return "", true
	}
	const p = "Basic "
	if !strings.HasPrefix(header, p) {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(header[len(p):])
	if err != nil {
		return "", false
	}
	name, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return "", false
	}
	want, ok := h.users[name]
	if !ok {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(pass)) != 1 {
		return "", false
	}
	return name, true
}

// remoteAddr 把 h3 server 提供的 r.RemoteAddr("ip:port")抬成 net.Addr,供接入器解真源(max-ips);空 → nil。
func remoteAddr(s string) net.Addr {
	if s == "" {
		return nil
	}
	return strAddr(s)
}

type strAddr string

func (strAddr) Network() string  { return "udp" }
func (a strAddr) String() string { return string(a) }
