package naive

import (
	"context"
	"crypto/subtle"
	cryptotls "crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sagernet/sing/common/metadata"

	"golang.org/x/net/http2"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
)

var _ endpoint.InboundHandler = (*Inbound)(nil)

const naiveServerIdleTimeout = 5 * time.Minute

// User 是 NaiveProxy 服务端用户(名 + 密码,HTTP Basic 认证)。
type User struct {
	Name     string
	Password string
}

// Inbound 是 NaiveProxy 入站:一条 TLS 连接 → H2 服务端 → 多条带填充的 CONNECT 流,
// 每条按目标路由到出站。NTR 管 TCP 监听(InboundHandler),TLS+H2 在拿到的 stream 上做。
type Inbound struct {
	tlsConfig *cryptotls.Config
	users     map[string]string // name → password
	out       endpoint.Outbound
	dispatch  endpoint.StreamDispatch
}

// NewInbound 构造 NaiveProxy 入站(服务端证书 + Basic 用户 + 绑定出站)。
func NewInbound(users []User, tlsConfig *cryptotls.Config, out endpoint.Outbound, dispatch endpoint.StreamDispatch) (*Inbound, error) {
	m := make(map[string]string, len(users))
	for _, u := range users {
		if u.Name != "" {
			m[u.Name] = u.Password
		}
	}
	if len(m) == 0 {
		return nil, errors.New("naive: 入站需至少一个 user{name,password}")
	}
	tlsConfig.NextProtos = []string{"h2"}
	return &Inbound{tlsConfig: tlsConfig, users: m, out: out, dispatch: dispatch}, nil
}

// HandleStream:对一条 TCP 连接做 TLS + H2 服务端,解复用其上的 CONNECT 流。阻塞至 H2 连接结束。
func (h *Inbound) HandleStream(ctx context.Context, s link.Stream, _ *endpoint.Metadata) error {
	tc := cryptotls.Server(s, h.tlsConfig)
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	(&http2.Server{IdleTimeout: naiveServerIdleTimeout}).ServeConn(tc, &http2.ServeConnOpts{
		Context: ctx,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.serve(ctx, w, r) }),
	})
	return nil
}

// HandlePacket:NaiveProxy 无 PacketConn 入站。
func (h *Inbound) HandlePacket(context.Context, link.PacketConn, *endpoint.Metadata) error {
	return errors.New("naive: packet inbound not supported")
}

// serve 处理一条 H2 请求:必须是 CONNECT + 带 Padding 头 + Basic 认证通过,
// 回 200(带 Padding 头)后按目标建流路由。handler 阻塞至 relay 收尾(保持 H2 流存活)。
func (h *Inbound) serve(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Padding") == "" { // naive 必带 Padding 头,缺 = 非 naive 客户端
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.checkAuth(r.Header.Get("Proxy-Authorization")) {
		http.Error(w, "proxy auth required", http.StatusProxyAuthRequired) // 407
		return
	}
	authority := r.URL.Host
	if authority == "" {
		authority = r.Host
	}
	if authority == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flush", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Padding", generatePaddingHeader())
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	dst := toNTR(metadata.ParseSocksaddr(authority))
	st := &paddedStream{
		r:       r.Body,
		w:       w,
		flush:   flusher.Flush,
		closeFn: r.Body.Close,
	}
	if h.dispatch != nil { // 反连 portal:已握手流交隧道派发,不落地出站
		_ = h.dispatch(ctx, st, dst, endpoint.NetworkTCP)
		return
	}
	up, err := h.out.DialStream(ctx, dst)
	if err != nil {
		_ = st.Close()
		return
	}
	_ = relay.Relay(st, up) // 阻塞至收尾,保持 handler(H2 流)存活
}

// checkAuth 校验 "Basic base64(user:pass)":解出用户查表,常量时间比对密码。
func (h *Inbound) checkAuth(header string) bool {
	const p = "Basic "
	if !strings.HasPrefix(header, p) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(header[len(p):])
	if err != nil {
		return false
	}
	name, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	want, ok := h.users[name]
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(pass)) == 1
}

func toNTR(a metadata.Socksaddr) addr.Socksaddr {
	return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}
