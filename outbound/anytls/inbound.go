package anytls

import (
	"context"
	cryptotls "crypto/tls"
	"errors"
	"net"
	"sync"

	sanytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/auth"
	sbuf "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
)

var _ endpoint.InboundHandler = (*Inbound)(nil)

// User 是 AnyTLS 服务端用户(名 + 密码)。
type User = sanytls.User

// UserFromContext 读 sing-anytls(sagernet/sing fork)鉴权命中后经 auth.ContextWithUser 写入的用户 tag。
// 供 config 的会话式计量 dispatch 回读身份 → 映 cred.ID(承第4章顶层 users;tag = BillID)。
func UserFromContext(ctx context.Context) (string, bool) { return auth.UserFromContext[string](ctx) }

// Inbound 是 AnyTLS 会话解复用入站:一条 TLS 连接 → anytls 会话 → 多条复用流,每条路由到出站。
type Inbound struct {
	service   *sanytls.Service
	tlsConfig *cryptotls.Config
}

// NewInbound 构造 AnyTLS 入站(服务端证书 + 用户 + 绑定出站)。
func NewInbound(users []User, tlsConfig *cryptotls.Config, out endpoint.Outbound, dispatch endpoint.StreamDispatch) (*Inbound, error) {
	svc, err := sanytls.NewService(sanytls.ServiceConfig{
		Users:         users,
		Handler:       &routeHandler{out: out, dispatch: dispatch},
		Logger:        logger.NOP(),
		PaddingScheme: padding.DefaultPaddingScheme,
	})
	if err != nil {
		return nil, err
	}
	return &Inbound{service: svc, tlsConfig: tlsConfig}, nil
}

// HandleStream:对每条接受的 TCP 连接做 TLS,再交 anytls 会话解复用(内部对每条子流回调路由)。
// 阻塞至该会话结束。
func (h *Inbound) HandleStream(ctx context.Context, s link.Stream, _ *endpoint.Metadata) error {
	tc := cryptotls.Server(s, h.tlsConfig)
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	return h.service.NewConnection(ctx, tc, M.Socksaddr{}, func(error) {})
}

// HandlePacket:AnyTLS 无原生 PacketConn 入站。
func (h *Inbound) HandlePacket(context.Context, link.PacketConn, *endpoint.Metadata) error {
	return errors.New("anytls: packet inbound not supported")
}

// routeHandler 路由每条解复用出来的代理流:按 destination 拨出站 + 双向中继。
type routeHandler struct {
	out      endpoint.Outbound
	dispatch endpoint.StreamDispatch
}

func (h *routeHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	// UoT:客户端把 UDP 走成「到 uot 魔术地址的一条普通复用流」。识别后读 uot 请求头、以 uot 帧承载
	// UDP 包,按 per-packet dst 落地(多目标),与 sing-box anytls 服务端一致(禁改线格式:UDP 全在 uot 层)。
	if destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress {
		err := h.serveUOT(ctx, conn)
		if onClose != nil {
			onClose(err)
		}
		return
	}
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
	err = relay.Relay(connStream{conn}, up) // Relay 内部收尾两端
	if onClose != nil {
		onClose(err)
	}
}

// serveUOT 把一条 uot 承载流中继到出站 UDP:上行读 uot 帧(带 per-packet dst)→ 出站 DialPacket(多目标)
// WritePacket;下行把出站回包写回 uot 帧。首包懒拨出站,单条多目标复用同一出站 PacketConn(同 mieru serveUDP)。
func (h *routeHandler) serveUOT(ctx context.Context, conn net.Conn) error {
	request, err := uot.ReadRequest(conn)
	if err != nil {
		_ = conn.Close()
		return err
	}
	uc := uot.NewConn(conn, *request) // *uot.Conn 实现 N.NetPacketConn:ReadPacket/WritePacket 带 M.Socksaddr
	defer uc.Close()
	var (
		mu     sync.Mutex
		pc     link.PacketConn
		dlOnce sync.Once
	)
	for {
		// ★用 ReadPacket(得 M.Socksaddr)而非 ReadFrom(它把地址降成 *net.UDPAddr、丢 FQDN → 域名目标解不出端口)。
		sb := sbuf.NewPacket()
		destination, rerr := uc.ReadPacket(sb)
		if rerr != nil {
			sb.Release()
			break
		}
		target := toNTR(destination) // 保留 FQDN
		mu.Lock()
		if pc == nil {
			pc, err = h.out.DialPacket(ctx, target)
			if err != nil {
				mu.Unlock()
				sb.Release()
				break
			}
			cur := pc
			dlOnce.Do(func() { go uotDownlink(cur, uc) })
		}
		cur := pc
		mu.Unlock()
		wb := buf.New()
		_, _ = wb.Write(sb.Bytes())
		sb.Release()
		if werr := cur.WritePacket(wb, target); werr != nil {
			break
		}
	}
	mu.Lock()
	if pc != nil {
		_ = pc.Close()
	}
	mu.Unlock()
	return nil
}

// uotDownlink 把出站回包(link.PacketConn)重新写回 uot 承载流,源地址原样带回(uc.WriteTo 接受 net.Addr)。
func uotDownlink(pc link.PacketConn, uc net.PacketConn) {
	for {
		b := buf.New()
		src, err := pc.ReadPacket(b)
		if err != nil {
			return
		}
		if _, err := uc.WriteTo(b.Bytes(), toSing(src)); err != nil {
			return
		}
	}
}
