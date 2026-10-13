package masque

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	mhttp "github.com/metacubex/http"
	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	mtls "github.com/metacubex/tls"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
)

// User 是 MASQUE 服务端用户(可选的 HTTP Basic 保护;为空则不鉴权)。
type User struct {
	Name     string
	Password string
}

type ctxUserKey struct{}

// withUser 把 Basic 认证到的计费用户名挂进 ctx(供 dispatch 计量回读;未鉴权模式下名为空=Ambient)。
func withUser(ctx context.Context, name string) context.Context {
	if name == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxUserKey{}, name)
}

// UserFromContext 读认证命中的计费用户名(供 config 的 SessionDispatch 回读 → cred.ID 计量)。
func UserFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(ctxUserKey{}).(string)
	return name, ok && name != ""
}

// Inbound 是 MASQUE 入站:在 UDP socket 上跑 QUIC + HTTP/3 服务端,处理
// connect-udp(RFC 9298,UDP over HTTP Datagram)与普通 CONNECT(RFC 9220,TCP over h3)。
// 自管 UDP 监听(Run),不走 NTR 的 TCP 接入环。
type Inbound struct {
	tlsConfig *mtls.Config
	users     map[string]string
	out       endpoint.Outbound
	dispatch  endpoint.StreamDispatch
	packet    endpoint.PacketDispatch
	srv       *http3.Server
}

// NewInbound 构造 MASQUE 入站(服务端 TLS + 可选 Basic 用户 + 绑定出站)。
// dispatch 非 nil 时 TCP 流改派给它(计量 / 反连 portal)。packet 接手 connect-udp 会话(运行时准入计量 +
// 路由;portal 口桥进隧道);nil = connect-udp 回 501。
func NewInbound(users []User, tlsConfig *mtls.Config, out endpoint.Outbound, dispatch endpoint.StreamDispatch, packet endpoint.PacketDispatch) (*Inbound, error) {
	m := make(map[string]string, len(users))
	for _, u := range users {
		if u.Name != "" {
			m[u.Name] = u.Password
		}
	}
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	h := &Inbound{tlsConfig: tlsConfig, users: m, out: out, dispatch: dispatch, packet: packet}
	// Extended CONNECT 在 metacubex/quic-go 的 h3 服务端是硬编码常开的;datagram 要显式开。
	h.srv = &http3.Server{
		EnableDatagrams: true,
		Handler:         mhttp.HandlerFunc(h.serve),
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
	// ★ QUIC 层必须开 datagram:h3 的 SETTINGS 只声明能力,真正收发要靠 QUIC 层支持。
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
		go func() { _ = h.srv.ServeQUICConn(conn) }() // ServeQUICConn 不负责关 conn
	}
}

// serve 处理一条 h3 请求:CONNECT + (可选)Basic 认证;
// :protocol=connect-udp → UDP 隧道;普通 CONNECT → TCP 隧道。
func (h *Inbound) serve(w mhttp.ResponseWriter, r *mhttp.Request) {
	if r.Method != mhttp.MethodConnect {
		mhttp.Error(w, "method not allowed", mhttp.StatusMethodNotAllowed)
		return
	}
	name, ok := h.authUser(r.Header.Get("Proxy-Authorization"))
	if !ok {
		mhttp.Error(w, "proxy auth required", mhttp.StatusProxyAuthRequired)
		return
	}
	ctx := withUser(r.Context(), name) // 认证到的计费用户名挂 ctx(未鉴权=Ambient),供 dispatch 计量回读
	if r.Proto == connectUDPProto {    // Extended CONNECT:RFC 9298
		h.serveUDP(ctx, w, r)
		return
	}
	h.serveTCP(ctx, w, r)
}

// serveUDP 处理 connect-udp:从 URI 模板解出目标,回 200 后接管流,把 HTTP Datagram 会话包成单目标
// link.PacketConn 交运行时 PacketDispatch(准入 + 计量 + 路由;portal 口整条桥进隧道)。
func (h *Inbound) serveUDP(ctx context.Context, w mhttp.ResponseWriter, r *mhttp.Request) {
	dst, err := parseConnectUDPPath(r.URL.Path)
	if err != nil {
		mhttp.Error(w, "bad target", mhttp.StatusBadRequest)
		return
	}
	if h.packet == nil {
		mhttp.Error(w, "connect-udp disabled", mhttp.StatusNotImplemented)
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		mhttp.Error(w, "no hijack", mhttp.StatusInternalServerError)
		return
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(mhttp.StatusOK)
	hs := streamer.HTTPStream()                                                                    // 接管:内部置 hijacked 并 flush 响应头,此后由本方负责 Close
	_ = h.packet(ctx, &datagramConn{hs: hs, dst: dst, remote: remoteAddr(r.RemoteAddr), ctx: ctx}) // 返回时已关 hs
}

// serveTCP 处理普通 CONNECT(RFC 9220):目标在 :authority,回 200 后接管流双向 relay。
func (h *Inbound) serveTCP(ctx context.Context, w mhttp.ResponseWriter, r *mhttp.Request) {
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	if authority == "" {
		mhttp.Error(w, "bad request", mhttp.StatusBadRequest)
		return
	}
	dst, err := parseHostPort(authority)
	if err != nil {
		mhttp.Error(w, "bad target", mhttp.StatusBadRequest)
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		mhttp.Error(w, "no hijack", mhttp.StatusInternalServerError)
		return
	}
	w.WriteHeader(mhttp.StatusOK)
	hs := streamer.HTTPStream()
	st := &serverStream{s: hs, remote: remoteAddr(r.RemoteAddr)} // h3 server 提供真客户端地址 → max-ips
	if h.dispatch != nil {                                       // 反连 portal:已握手流交隧道派发,不落地出站
		_ = h.dispatch(ctx, st, dst, endpoint.NetworkTCP)
		return
	}
	up, err := h.out.DialStream(ctx, dst)
	if err != nil {
		_ = st.Close()
		return
	}
	_ = relay.Relay(st, up) // Relay 内部收尾两端
}

// datagramConn 把一条 connect-udp 流(RFC 9298:HTTP Datagram,Context-ID 0 + UDP 载荷)适配成单目标
// link.PacketConn(服务端侧客户端连接):ReadPacket 剥 Context-ID、恒报握手目标;WritePacket 前置 Context-ID 0
// 发出。deadline 经 ctx 落到 ReceiveDatagram(运行时 udpNAT 每读前 arm 空闲超时)。
type datagramConn struct {
	hs     *http3.Stream
	dst    addr.Socksaddr
	remote net.Addr
	ctx    context.Context

	mu       sync.Mutex
	deadline time.Time
}

var _ link.PacketConn = (*datagramConn)(nil)

func (c *datagramConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	for {
		c.mu.Lock()
		d := c.deadline
		c.mu.Unlock()
		ctx, cancel := c.ctx, context.CancelFunc(func() {})
		if !d.IsZero() {
			ctx, cancel = context.WithDeadline(c.ctx, d)
		}
		data, err := c.hs.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			return addr.Socksaddr{}, err
		}
		payload, ok := stripContextID(data)
		if !ok || len(payload) > b.Tailroom() {
			continue // 非零 context-id / 畸形 / 超缓冲:按 RFC 丢弃
		}
		copy(b.ExtendTail(len(payload)), payload)
		return c.dst, nil
	}
}

func (c *datagramConn) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error {
	if b.Len() > udpPayloadMax {
		return nil // 超 RFC 上限,丢弃
	}
	if b.Headroom() >= 1 {
		hdr := b.ExtendHeader(1)
		hdr[0] = 0x00 // Context ID = 0
		return c.hs.SendDatagram(b.Bytes())
	}
	return c.hs.SendDatagram(append([]byte{0x00}, b.Bytes()...))
}

func (c *datagramConn) Close() error         { return c.hs.Close() }
func (c *datagramConn) LocalAddr() net.Addr  { return masqueAddr{} }
func (c *datagramConn) RemoteAddr() net.Addr { return c.remote }
func (c *datagramConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *datagramConn) Unwrap() any { return nil }

// parseConnectUDPPath 从 RFC 9298 URI 模板解出目标:
// /.well-known/masque/udp/{target_host}/{target_port}/ (path 已由 http3 解码,IPv6 冒号已还原)。
func parseConnectUDPPath(path string) (addr.Socksaddr, error) {
	const prefix = "/.well-known/masque/udp/"
	if !strings.HasPrefix(path, prefix) {
		return addr.Socksaddr{}, errors.New("masque: 非 connect-udp 模板路径")
	}
	rest := strings.Trim(strings.TrimPrefix(path, prefix), "/")
	i := strings.LastIndex(rest, "/")
	if i <= 0 {
		return addr.Socksaddr{}, errors.New("masque: 模板缺 host/port")
	}
	host, portStr := rest[:i], rest[i+1:]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return addr.Socksaddr{}, errors.New("masque: 端口非法")
	}
	if host == "" {
		return addr.Socksaddr{}, errors.New("masque: host 为空")
	}
	return parseHostPort(net.JoinHostPort(host, portStr))
}

// parseHostPort 把 host:port 解析成 Socksaddr(IP 走 Addr,域名走 Fqdn)。
func parseHostPort(hostPort string) (addr.Socksaddr, error) {
	h, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		return addr.Socksaddr{}, err
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return addr.Socksaddr{}, err
	}
	if ip, perr := netip.ParseAddr(h); perr == nil {
		return addr.FromIPPort(netip.AddrPortFrom(ip, uint16(port))), nil
	}
	return addr.FromFqdn(h, uint16(port)), nil
}

// authUser:未配用户 = 不鉴权(返回 "",true → Ambient);配了则校验 "Basic base64(user:pass)",
// 成功返回命中的用户名。
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

func basicAuth(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// serverStream 把服务端接管的 *http3.Stream 抬成 link.Stream。
type serverStream struct {
	s      *http3.Stream
	remote net.Addr // 底层 QUIC 真实客户端地址(h3 server 从 r.RemoteAddr 提供),供 max-ips 按真源计
}

func (s *serverStream) Read(p []byte) (int, error)  { return s.s.Read(p) }
func (s *serverStream) Write(p []byte) (int, error) { return s.s.Write(p) }
func (s *serverStream) Close() error                { return s.s.Close() }
func (*serverStream) LocalAddr() net.Addr           { return masqueAddr{} }
func (s *serverStream) RemoteAddr() net.Addr {
	if s.remote != nil {
		return s.remote
	}
	return masqueAddr{}
}
func (*serverStream) SetDeadline(time.Time) error      { return nil }
func (*serverStream) SetReadDeadline(time.Time) error  { return nil }
func (*serverStream) SetWriteDeadline(time.Time) error { return nil }
func (*serverStream) Unwrap() any                      { return nil }
