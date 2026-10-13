package juicity

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sagernet/quic-go"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
)

const (
	authTimeout = 10 * time.Second // 与官方服务端一致:连接建立后 10s 内须完成鉴权
	// serverMaxStreams:规范要求服务端 maxOpenIncomingStreams ≥ 30。
	serverMaxStreams = 1024

	errCodeAuthFailed quic.ApplicationErrorCode = 0xfff0 // 鉴权失败关连接(官方复用 TUIC 的码,客户端不依赖具体值)
)

// User 是 Juicity 服务端用户(复合键 = UUID + Password)。Name 是计量 tag(顶层 users = BillID);空 = UUID。
type User struct {
	Name     string
	UUID     string
	Password string
}

type ctxKeyUser struct{}

// UserFromContext 读鉴权命中的用户 tag(供运行时计量回读身份)。
func UserFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeyUser{}).(string)
	return v, ok && v != ""
}

// InboundOptions 是 Juicity 入站配置。对内核只用协议无关的 core 契约,不 import 运行时。
type InboundOptions struct {
	Users []User
	TLS   *tls.Config // 服务端证书;ALPN/TLS 版本由本包强制为 h3 / ≥1.3

	Out endpoint.Outbound // 默认出站(Dispatch 为 nil 时 TCP 直接 relay 到它)

	// Dispatch 处理 TCP 代理流(计量 / 反连 portal);nil = relay 到 Out。
	Dispatch endpoint.StreamDispatch
	// Admit 对 UDP 承载流做准入 + 计量(UDP 字节随承载流计入用户);nil = 不计量。
	Admit endpoint.AdmitHook
	// PacketDispatch 接手 UDP 会话(按包目标拆分路由 = udpNAT);nil = 不支持 UDP(关流)。
	PacketDispatch endpoint.PacketDispatch
}

// Inbound 是 Juicity 入站:UDP 上跑 QUIC,鉴权(UUID+password)后把每条代理流交给内核。
type Inbound struct {
	users    map[[16]byte]User
	tlsConf  *tls.Config
	quicConf *quic.Config
	o        InboundOptions
}

// NewInbound 构造 Juicity 入站。
func NewInbound(o InboundOptions) (*Inbound, error) {
	if o.TLS == nil {
		return nil, errors.New("juicity: 入站需 TLS 证书")
	}
	if len(o.Users) == 0 {
		return nil, errors.New("juicity: 入站需至少一个用户")
	}
	if o.Out == nil && o.Dispatch == nil {
		return nil, errors.New("juicity: 入站需出站或派发器")
	}
	users := make(map[[16]byte]User, len(o.Users))
	for _, u := range o.Users {
		id, err := parseUUID(u.UUID)
		if err != nil {
			return nil, err
		}
		if u.Name == "" {
			u.Name = u.UUID
		}
		users[id] = u
	}
	tc := o.TLS.Clone()
	tc.NextProtos = []string{"h3"}
	tc.MinVersion = tls.VersionTLS13
	return &Inbound{
		users:   users,
		tlsConf: tc,
		quicConf: &quic.Config{
			MaxIncomingStreams:    serverMaxStreams,
			MaxIncomingUniStreams: 16,
			MaxIdleTimeout:        idleTimeout,
			KeepAlivePeriod:       keepAlive,
		},
		o: o,
	}, nil
}

// Run 绑定 UDP 监听并服务,阻塞至 ctx 取消。
func (h *Inbound) Run(ctx context.Context, listen string) error {
	ua, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	defer pc.Close()
	return h.Serve(ctx, pc)
}

// Serve 在已绑定的 UDP socket 上接受 QUIC 连接。
func (h *Inbound) Serve(ctx context.Context, pc net.PacketConn) error {
	ln, err := quic.Listen(pc, h.tlsConf, h.quicConf)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go h.handleConn(ctx, conn)
	}
}

func (h *Inbound) handleConn(ctx context.Context, conn *quic.Conn) {
	setCongestion(conn, "bbr")
	go func() { // 服务停止时拆连接
		select {
		case <-ctx.Done():
			_ = conn.CloseWithError(0, "")
		case <-conn.Context().Done():
		}
	}()
	authed := make(chan struct{})
	var user User
	go func() {
		u, err := h.authenticate(conn)
		if err != nil {
			_ = conn.CloseWithError(errCodeAuthFailed, "")
			return
		}
		user = u // 写于 close(authed) 之前,读者在 <-authed 之后读 —— channel 关闭建立 happens-before
		close(authed)
	}()
	for {
		st, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		go h.handleStream(ctx, conn, st, authed, &user)
	}
}

// authenticate 在单向流上读鉴权命令并校验 token;通过后继续读掉该流余下内容
// (新版客户端会在此续写 underlay 鉴权帧,本实现不支持该特性,读掉以免流控卡住对端)。
func (h *Inbound) authenticate(conn *quic.Conn) (User, error) {
	actx, cancel := context.WithTimeout(conn.Context(), authTimeout)
	defer cancel()
	uni, err := conn.AcceptUniStream(actx)
	if err != nil {
		return User{}, fmt.Errorf("juicity: 等鉴权流: %w", err)
	}
	_ = uni.SetReadDeadline(time.Now().Add(authTimeout))
	id, tok, err := readAuth(uni)
	if err != nil {
		return User{}, err
	}
	u, ok := h.users[id]
	if !ok {
		return User{}, errors.New("juicity: 未知用户")
	}
	want, err := genToken(conn.ConnectionState().TLS, id, u.Password)
	if err != nil {
		return User{}, err
	}
	if subtle.ConstantTimeCompare(want[:], tok[:]) != 1 {
		return User{}, errors.New("juicity: token 不符")
	}
	_ = uni.SetReadDeadline(time.Time{})
	go func() { _, _ = io.Copy(io.Discard, uni) }()
	return u, nil
}

func (h *Inbound) handleStream(ctx context.Context, conn *quic.Conn, st *quic.Stream, authed <-chan struct{}, user *User) {
	sc := newStreamConn(st, conn, nil)
	_ = sc.SetReadDeadline(time.Now().Add(authTimeout))
	network, dst, err := readStreamHeader(sc)
	_ = sc.SetReadDeadline(time.Time{})
	if err != nil {
		_ = sc.Close()
		return
	}
	select { // 鉴权通过后才处理代理流(与官方服务端一致)
	case <-authed:
	case <-conn.Context().Done():
		_ = sc.Close()
		return
	}
	uctx := context.WithValue(ctx, ctxKeyUser{}, user.Name)
	switch network {
	case networkTCP:
		if h.o.Dispatch != nil {
			_ = h.o.Dispatch(uctx, sc, dst, endpoint.NetworkTCP)
			return
		}
		up, err := h.o.Out.DialStream(uctx, dst)
		if err != nil {
			_ = sc.Close()
			return
		}
		_ = relay.Relay(sc, up)
	case networkUDP:
		h.handleUDP(uctx, sc)
	}
}

// handleUDP:承载流先过准入 + 计量,再以 UDP 帧语义交给 PacketDispatch 按包目标路由。
// 流首里的地址只是客户端开流时的首目标,真正目标逐帧给出(官方服务端同样按首帧目标起拨)。
func (h *Inbound) handleUDP(ctx context.Context, sc *streamConn) {
	if h.o.PacketDispatch == nil {
		_ = sc.Close()
		return
	}
	var carrier link.Stream = sc
	if h.o.Admit != nil {
		ms, release, err := h.o.Admit(ctx, sc)
		if err != nil {
			return // 被拒时 Admit 已关流
		}
		defer release()
		carrier = ms
	}
	_ = h.o.PacketDispatch(ctx, &packetConn{s: carrier})
}
