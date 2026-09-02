package hysteria1

import (
	"context"
	cryptotls "crypto/tls"
	"net"

	shysteria "github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
)

// User 是 Hysteria v1 服务端用户(名 + 密码;Name 用作 sing 库内 tag,顶层 users 场景 = BillID)。
type User struct {
	Name     string
	Password string
}

// UserFromContext 读 hy1 库(sagernet/sing fork)鉴权命中后经 auth.ContextWithUser 写入的用户 tag。
// 供 config 的会话式接入 hook 回读身份 → 映 cred.ID(承第4章顶层 users;tag = BillID)。
func UserFromContext(ctx context.Context) (string, bool) { return auth.UserFromContext[string](ctx) }

// Inbound 是 Hysteria v1 入站:UDP 上跑 QUIC Service,鉴权(password)+ 解复用,每流路由到出站。
// 自管 UDP 监听(Run),不走 NTR 的 TCP 接入环。
type Inbound struct {
	service *shysteria.Service[string]
}

// NewInbound 构造 Hysteria v1 入站(服务端 TLS + 用户 + salamander 混淆 + 绑定出站)。admit 非 nil 时每条
// 已握手流先过接入(闸+计量+mem-guard),拿计量流后再回协议握手信令 relay(承世界 C;不代管 relay 因 hy1
// 落地前必须 ReportConnHandshakeSuccess)。
func NewInbound(users []User, obfs string, upMbps, downMbps uint64, tlsConfig *cryptotls.Config, out endpoint.Outbound, dispatch endpoint.StreamDispatch, admit endpoint.AdmitHook) (*Inbound, error) {
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
		Handler:       &routeHandler{out: out, dispatch: dispatch, admit: admit},
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(users))
	pws := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, u.Name) // ★库内 tag = Name(顶层 users = BillID);此前误填 password,回读拿不到 BillID
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
	admit    endpoint.AdmitHook
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
	// 接入(闸+计量+mem-guard):拿计量流 ms + release;★handshake 信令仍在【裸 conn】上做(计量只包 payload
	// relay,不碰协议握手字节)。admit 为 nil(未接入)时 ms=裸流、release 空操作。
	var ms link.Stream = connStream{conn}
	release := func() {}
	if h.admit != nil {
		m, rel, aerr := h.admit(ctx, connStream{conn})
		if aerr != nil { // 被拒(限额/停用/mem-guard):admit 已关 conn
			if onClose != nil {
				onClose(aerr)
			}
			return
		}
		ms, release = m, rel
	}
	defer release()
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
	if hErr := N.ReportConnHandshakeSuccess(conn, up); hErr != nil { // ★在裸 conn 上回握手信令
		_ = conn.Close()
		_ = up.Close()
		if onClose != nil {
			onClose(hErr)
		}
		return
	}
	err = relay.Relay(ms, up) // 计量流(payload 计到 who);握手字节已在裸 conn 上发完,不计
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
