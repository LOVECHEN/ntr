package trusttunnel

import (
	"context"
	"crypto/subtle"
	cryptotls "crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	mtls "github.com/metacubex/tls"
	"github.com/sagernet/sing/common/metadata"

	"golang.org/x/net/http2"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
)

var _ endpoint.InboundHandler = (*Inbound)(nil)

const ttServerIdleTimeout = 5 * time.Minute

type ctxUserKey struct{}

// withUser 把 Basic 认证到的计费用户名挂进 ctx(供 dispatch 计量回读)。
func withUser(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, ctxUserKey{}, name)
}

// UserFromContext 读认证命中的计费用户名(供 config 的 SessionDispatch 回读 → cred.ID 计量)。
func UserFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(ctxUserKey{}).(string)
	return name, ok && name != ""
}

// User 是 TrustTunnel 服务端用户(名 + 密码,HTTP Basic 认证)。
type User struct {
	Name     string
	Password string
}

// Inbound 是 TrustTunnel 入站:一条 TLS 连接 → H2 服务端 → 多条 CONNECT 流,每条按 :authority
// 目标路由到出站。NTR 管 TCP 监听(InboundHandler),TLS+H2 在拿到的 stream 上做。
type Inbound struct {
	tlsConfig *cryptotls.Config
	users     map[string]string // name → password
	out       endpoint.Outbound
	dispatch  endpoint.StreamDispatch
	packet    endpoint.PacketDispatch
	h3TLS     *mtls.Config // 非 nil = 同端口另开 UDP 跑 H3(见 h3.go)
}

// NewInbound 构造 TrustTunnel 入站(服务端证书 + Basic 用户 + 绑定出站)。
func NewInbound(users []User, tlsConfig *cryptotls.Config, out endpoint.Outbound, dispatch endpoint.StreamDispatch, packet endpoint.PacketDispatch) (*Inbound, error) {
	m := make(map[string]string, len(users))
	for _, u := range users {
		if u.Name != "" {
			m[u.Name] = u.Password
		}
	}
	if len(m) == 0 {
		return nil, errors.New("trusttunnel: 入站需至少一个 user{name,password}")
	}
	tlsConfig.NextProtos = []string{"h2"}
	return &Inbound{tlsConfig: tlsConfig, users: m, out: out, dispatch: dispatch, packet: packet}, nil
}

// HandleStream:对一条 TCP 连接做 TLS + H2 服务端,解复用其上的 CONNECT 流。阻塞至 H2 连接结束。
func (h *Inbound) HandleStream(ctx context.Context, s link.Stream, _ *endpoint.Metadata) error {
	tc := cryptotls.Server(s, h.tlsConfig)
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	srv := &http2.Server{IdleTimeout: ttServerIdleTimeout}
	srv.ServeConn(tc, &http2.ServeConnOpts{
		Context: ctx,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.serve(ctx, w, r) }),
	})
	return nil
}

// HandlePacket:TrustTunnel 无原生 PacketConn 入站(_udp2 复用在 CONNECT 流内,后置)。
func (h *Inbound) HandlePacket(context.Context, link.PacketConn, *endpoint.Metadata) error {
	return errors.New("trusttunnel: packet inbound not supported")
}

// tunnelReq 是一条 CONNECT 请求的协议无关视图(H2 / H3 各自适配),让 handle 只写一份 TrustTunnel 语义。
type tunnelReq struct {
	method, host, auth string
	remote             net.Addr
	reject             func(code int, msg string)  // 拒绝(不进隧道)
	accept             func() (link.Stream, error) // 回 200 并交出双向流
}

// serve 把一条 H2 请求适配成 tunnelReq。handler 阻塞至隧道收尾(保持 H2 流存活)。
func (h *Inbound) serve(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	remote := remoteAddr(r.RemoteAddr) // h2 server 设的真客户端地址 → max-ips 按真源计
	h.handle(ctx, tunnelReq{
		method: r.Method,
		host:   host,
		auth:   r.Header.Get("proxy-authorization"),
		remote: remote,
		reject: func(code int, msg string) { http.Error(w, msg, code) },
		accept: func() (link.Stream, error) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "no flush", http.StatusInternalServerError)
				return nil, errors.New("trusttunnel: h2 无 Flusher")
			}
			w.WriteHeader(http.StatusOK)
			flusher.Flush()
			return &h2Stream{r: r.Body, w: serverWriteFlusher{w: w, f: flusher}, closeFn: r.Body.Close, remote: remote}, nil
		},
	})
}

// handle 是 TrustTunnel 服务端语义:必须 CONNECT + Basic 认证通过;_check 心跳回 200;_udp2 交 PacketDispatch;
// _icmp 暂拒;其余按 :authority 目标建流路由(计量 / 反连 portal 经 dispatch)。
func (h *Inbound) handle(ctx context.Context, q tunnelReq) {
	if q.method != http.MethodConnect {
		q.reject(http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	name, ok := h.authUser(q.auth)
	if !ok {
		q.reject(http.StatusProxyAuthRequired, "proxy auth required") // 407
		return
	}
	ctx = withUser(ctx, name) // 认证到的计费用户名挂 ctx,供 dispatch 计量回读
	switch q.host {
	case "_check": // 健康检查心跳
		if st, err := q.accept(); err == nil {
			_ = st.Close()
		}
		return
	case udpMagic:
		if h.packet == nil {
			q.reject(http.StatusNotImplemented, "udp not enabled")
			return
		}
		st, err := q.accept()
		if err != nil {
			return
		}
		_ = h.packet(ctx, newFrameConn(st, false, q.remote)) // 运行时准入计量 + 按包目标路由;portal 口桥进隧道
		return
	case "_icmp":
		q.reject(http.StatusNotImplemented, "icmp not implemented")
		return
	}
	st, err := q.accept()
	if err != nil {
		return
	}
	dst := toNTR(metadata.ParseSocksaddr(q.host))
	if h.dispatch != nil { // 计量 / 反连 portal:已握手流交 dispatch
		_ = h.dispatch(ctx, st, dst, endpoint.NetworkTCP)
		return
	}
	up, err := h.out.DialStream(ctx, dst)
	if err != nil {
		_ = st.Close()
		return
	}
	_ = relay.Relay(st, up) // 阻塞至收尾,保持 handler(流)存活
}

// authUser 校验 "Basic base64(user:pass)":解出用户查表,常量时间比对密码;成功返回命中的用户名。
func (h *Inbound) authUser(header string) (string, bool) {
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

// serverWriteFlusher 把 H2 ResponseWriter 的写在每次 Write 后 flush(否则 h2 帧不发出)。
type serverWriteFlusher struct {
	w http.ResponseWriter
	f http.Flusher
}

func (s serverWriteFlusher) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if n > 0 {
		s.f.Flush()
	}
	return n, err
}

func toNTR(a metadata.Socksaddr) addr.Socksaddr {
	return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}
