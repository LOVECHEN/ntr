package tuic

import (
	"context"
	cryptotls "crypto/tls"
	"net"

	stuic "github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/relay"
)

// User 是 TUIC 服务端用户(库内 tag Name + UUID + 密码;复合键 = UUID+Password)。Name 用作 sing 库内
// tag(顶层 users = BillID);缺省 = UUID。
type User struct {
	Name     string
	UUID     string
	Password string
}

// UserFromContext 读 tuic 库(sagernet/sing fork)鉴权命中后经 auth.ContextWithUser 写入的用户 tag。
func UserFromContext(ctx context.Context) (string, bool) { return auth.UserFromContext[string](ctx) }

// Inbound 是 TUIC 入站:UDP 上跑 QUIC Service,接受 + 鉴权(UUID+password)+ 解复用,
// 每条代理流路由到出站。自管 UDP 监听(Run),不走 NTR 的 TCP 接入环。
type Inbound struct {
	service *stuic.Service[string]
}

// NewInbound 构造 TUIC 入站(服务端 TLS + 用户 + 绑定出站)。
func NewInbound(users []User, tlsConfig *cryptotls.Config, out endpoint.Outbound, dispatch endpoint.StreamDispatch) (*Inbound, error) {
	tlsConfig.NextProtos = []string{"h3"}
	svc, err := stuic.NewService[string](stuic.ServiceOptions{
		Context:           context.Background(),
		Logger:            logger.NOP(),
		TLSConfig:         &serverTLS{config: tlsConfig},
		Handler:           &routeHandler{out: out, dispatch: dispatch},
		CongestionControl: "bbr",
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(users))
	uuids := make([][16]byte, 0, len(users))
	pws := make([]string, 0, len(users))
	for _, u := range users {
		uu, err := parseUUID(u.UUID)
		if err != nil {
			return nil, err
		}
		name := u.Name // 库内 tag(顶层 users = BillID);缺省回退 UUID(垫片单用户)
		if name == "" {
			name = u.UUID
		}
		names = append(names, name)
		uuids = append(uuids, uu)
		pws = append(pws, u.Password)
	}
	svc.UpdateUsers(names, uuids, pws)
	return &Inbound{service: svc}, nil
}

// Run 绑定 UDP 监听并跑 TUIC Service,阻塞至 ctx 取消。
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

// Serve 在已绑定的 UDP socket 上跑 TUIC Service。
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
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
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
