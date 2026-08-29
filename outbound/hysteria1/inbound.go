package hysteria1

import (
	"context"
	cryptotls "crypto/tls"
	"net"

	shysteria "github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/relay"
)

// User 是 Hysteria v1 服务端用户(仅密码)。
type User struct {
	Password string
}

// Inbound 是 Hysteria v1 入站:UDP 上跑 QUIC Service,鉴权(password)+ 解复用,每流路由到出站。
// 自管 UDP 监听(Run),不走 NTR 的 TCP 接入环。
type Inbound struct {
	service *shysteria.Service[string]
}

// NewInbound 构造 Hysteria v1 入站(服务端 TLS + 用户 + salamander 混淆 + 绑定出站)。
func NewInbound(users []User, obfs string, upMbps, downMbps uint64, tlsConfig *cryptotls.Config, out endpoint.Outbound, dispatch endpoint.StreamDispatch) (*Inbound, error) {
	tlsConfig.NextProtos = []string{"hysteria"}
	up, down := upMbps, downMbps
	if up == 0 {
		up = defaultMbps
	}
	if down == 0 {
		down = defaultMbps
	}
	svc, err := shysteria.NewService[string](shysteria.ServiceOptions{
		Context:       context.Background(),
		Logger:        logger.NOP(),
		SendBPS:       mbpsToBPS(down), // 服务端「发」= 客户端「收」
		ReceiveBPS:    mbpsToBPS(up),
		XPlusPassword: obfs,
		TLSConfig:     &serverTLS{config: tlsConfig},
		Handler:       &routeHandler{out: out, dispatch: dispatch},
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(users))
	pws := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, u.Password)
		pws = append(pws, u.Password)
	}
	svc.UpdateUsers(names, pws)
	return &Inbound{service: svc}, nil
}

// Run 绑定 UDP 监听并跑 Service,阻塞至 ctx 取消。
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

// Serve 在已绑定的 UDP socket 上跑 Service。
func (h *Inbound) Serve(ctx context.Context, pc net.PacketConn) error {
	if err := h.service.Start(pc); err != nil {
		return err
	}
	<-ctx.Done()
	_ = h.service.Close()
	return ctx.Err()
}

// routeHandler 路由每条解复用的代理流。
type routeHandler struct {
	out      endpoint.Outbound
	dispatch endpoint.StreamDispatch
}

func (h *routeHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	dst := toNTR(destination)
	if h.dispatch != nil { // 反连 portal:已握手流交隧道派发,不落地出站
		err := h.dispatch(ctx, connStream{conn}, dst, endpoint.NetworkTCP)
		if onClose != nil {
			onClose(err)
		}
		return
	}
	up, err := h.out.DialStream(ctx, dst)
	if err != nil {
		// 回落地失败:发 ServerResponse{OK:false} 让客户端立即失败,而非空等。
		_ = N.ReportHandshakeFailure(conn, err)
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
		}
		return
	}
	// ★上游建连成功后必须主动回 Hysteria ServerResponse{OK:true}(经 serverConn.HandshakeSuccess)。
	// 原生 hysteria v1 客户端(apernet/mihomo)在发完 ClientRequest 后会「阻塞读 ServerResponse」
	// 才开始转发载荷;sagernet 客户端则把请求+载荷懒合并发送、不等响应。故服务端不主动回 OK 时,
	// 面向「客户端先说话」的协议(HTTP)会与 mihomo 死锁。sing-box 的 hysteria 入站同样在此点
	// ReportHandshakeSuccess —— 这里对齐其行为,不改任何线格式。
	// 用 ReportConnHandshakeSuccess(非 deprecated 的 ReportHandshakeSuccess):sing-quic 的
	// hysteria serverConn 只实现旧的 HandshakeSuccess(),新 API 会自动回落到它,行为等价。
	if hErr := N.ReportConnHandshakeSuccess(conn, up); hErr != nil {
		_ = conn.Close()
		_ = up.Close()
		if onClose != nil {
			onClose(hErr)
		}
		return
	}
	err = relay.Relay(connStream{conn}, up)
	if onClose != nil {
		onClose(err)
	}
}

func (h *routeHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(errUDPNotReady)
	}
}
