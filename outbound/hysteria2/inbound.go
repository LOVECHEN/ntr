package hysteria2

import (
	"context"
	"net"
	"time"

	"github.com/metacubex/sing-quic/hysteria2"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	mtls "github.com/metacubex/tls"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/relay"
)

// User 是 Hysteria2 服务端用户(名 + 密码)。
type User struct {
	Name     string
	Password string
}

// Inbound 是 Hysteria2 入站:在 UDP socket 上跑 QUIC Service,接受连接 + 鉴权 + 解复用,
// 每条代理流路由到出站。它自管 UDP 监听(Run),不走 NTR 的 TCP 接入环。
type Inbound struct {
	service *hysteria2.Service[string]
}

// NewInbound 构造 Hysteria2 入站(服务端 TLS + 用户 + 绑定出站)。dispatch 非 nil 时每条已握手流
// 改派给它(反连 portal),否则 relay 到 out。
func NewInbound(users []User, tlsConfig *mtls.Config, salamander string, out endpoint.Outbound, dispatch endpoint.StreamDispatch) (*Inbound, error) {
	tlsConfig.NextProtos = []string{"h3"} // hy2 ALPN
	svc, err := hysteria2.NewService[string](hysteria2.ServiceOptions{
		Context:            context.Background(),
		Logger:             logger.NOP(),
		TLSConfig:          tlsConfig,
		SalamanderPassword: salamander,
		Handler:            &routeHandler{out: out, dispatch: dispatch},
		UDPTimeout:         5 * time.Minute,
		UdpMTU:             1200,
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(users))
	pws := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, u.Name)
		pws = append(pws, u.Password)
	}
	svc.UpdateUsers(names, pws)
	return &Inbound{service: svc}, nil
}

// Run 绑定 UDP 监听并跑 hy2 Service,阻塞至 ctx 取消。
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
	return h.Serve(ctx, pc)
}

// Serve 在已绑定的 UDP socket 上跑 hy2 Service,阻塞至 ctx 取消。
func (h *Inbound) Serve(ctx context.Context, pc net.PacketConn) error {
	if err := h.service.Start(pc); err != nil {
		return err
	}
	<-ctx.Done()
	_ = h.service.Close()
	return ctx.Err()
}

// routeHandler 路由每条解复用的代理流:按 destination 拨出站 + 双向中继;dispatch 非 nil 则改派
// 给它(反连 portal 把已握手流交隧道,不落地出站)。
type routeHandler struct {
	out      endpoint.Outbound
	dispatch endpoint.StreamDispatch
}

func (h *routeHandler) NewConnection(ctx context.Context, conn net.Conn, md M.Metadata) error {
	dst := toNTR(md.Destination)
	if h.dispatch != nil {
		return h.dispatch(ctx, connStream{conn}, dst, endpoint.NetworkTCP)
	}
	up, err := h.out.DialStream(ctx, dst)
	if err != nil {
		_ = conn.Close()
		return err
	}
	return relay.Relay(connStream{conn}, up)
}

func (h *routeHandler) NewPacketConnection(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
	// 拒绝 UDP 前必须关 conn:库侧 go 调本回调且丢弃返回值、不兜底 Close,不关则该 udpPacketConn
	// (含缓冲 channel)滞留 serverSession.udpConnMap 直到整条 QUIC 连接结束,认证后可累积泄漏。
	// 与 tuic/hysteria1 的 NewPacketConnectionEx 一致(它们都显式 Close)。
	_ = conn.Close()
	return errUDPNotReady
}
