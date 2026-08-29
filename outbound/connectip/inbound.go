//go:build with_connectip

package connectip

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
}

// InboundOptions 是 CONNECT-IP 入站配置。
type InboundOptions struct {
	AssignAddress string // 下发给客户端的隧道内地址(CIDR),如 10.9.0.2/32
	MTU           int
	ExtraSettings map[uint64]uint64 // 与客户端对齐用(如 Cloudflare 的 0x276)
}

// NewInbound 构造 CONNECT-IP 入站。
func NewInbound(o InboundOptions, tlsAny any, out endpoint.Outbound) (*Inbound, error) {
	tlsConfig, ok := tlsAny.(*mtls.Config)
	if !ok {
		return nil, errors.New("connect-ip: 需要 *metacubex/tls.Config")
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
	h := &Inbound{tlsConfig: tlsConfig, out: out, assignIP: assign, mtu: mtu}
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
