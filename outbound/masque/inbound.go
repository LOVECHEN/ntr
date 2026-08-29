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

// Inbound 是 MASQUE 入站:在 UDP socket 上跑 QUIC + HTTP/3 服务端,处理
// connect-udp(RFC 9298,UDP over HTTP Datagram)与普通 CONNECT(RFC 9220,TCP over h3)。
// 自管 UDP 监听(Run),不走 NTR 的 TCP 接入环。
type Inbound struct {
	tlsConfig *mtls.Config
	users     map[string]string
	out       endpoint.Outbound
	dispatch  endpoint.StreamDispatch
	srv       *http3.Server
}

// NewInbound 构造 MASQUE 入站(服务端 TLS + 可选 Basic 用户 + 绑定出站)。
// dispatch 非 nil 时 TCP 流改派给它(反连 portal)。
func NewInbound(users []User, tlsConfig *mtls.Config, out endpoint.Outbound, dispatch endpoint.StreamDispatch) (*Inbound, error) {
	m := make(map[string]string, len(users))
	for _, u := range users {
		if u.Name != "" {
			m[u.Name] = u.Password
		}
	}
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	h := &Inbound{tlsConfig: tlsConfig, users: m, out: out, dispatch: dispatch}
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
	if !h.checkAuth(r.Header.Get("Proxy-Authorization")) {
		mhttp.Error(w, "proxy auth required", mhttp.StatusProxyAuthRequired)
		return
	}
	if r.Proto == connectUDPProto { // Extended CONNECT:RFC 9298
		h.serveUDP(w, r)
		return
	}
	h.serveTCP(w, r)
}

// serveUDP 处理 connect-udp:从 URI 模板解出目标,回 200 后接管流,用 HTTP Datagram 双向搬 UDP。
func (h *Inbound) serveUDP(w mhttp.ResponseWriter, r *mhttp.Request) {
	dst, err := parseConnectUDPPath(r.URL.Path)
	if err != nil {
		mhttp.Error(w, "bad target", mhttp.StatusBadRequest)
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		mhttp.Error(w, "no hijack", mhttp.StatusInternalServerError)
		return
	}
	ctx := r.Context()
	pc, err := h.out.DialPacket(ctx, dst)
	if err != nil {
		mhttp.Error(w, "dial failed", mhttp.StatusBadGateway)
		return
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(mhttp.StatusOK)
	hs := streamer.HTTPStream() // 接管:内部置 hijacked 并 flush 响应头,此后由本方负责 Close
	defer hs.Close()
	defer pc.Close()
	_ = relayDatagram(ctx, hs, pc, dst)
}

// serveTCP 处理普通 CONNECT(RFC 9220):目标在 :authority,回 200 后接管流双向 relay。
func (h *Inbound) serveTCP(w mhttp.ResponseWriter, r *mhttp.Request) {
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
	ctx := r.Context()
	w.WriteHeader(mhttp.StatusOK)
	hs := streamer.HTTPStream()
	st := &serverStream{s: hs}
	if h.dispatch != nil { // 反连 portal:已握手流交隧道派发,不落地出站
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

// relayDatagram 在一条 connect-udp 流与上游 UDP 之间双向搬包:
// 上行剥 Context-ID → WritePacket;下行 ReadPacket → 前置 Context-ID 0 发出。
func relayDatagram(ctx context.Context, hs *http3.Stream, pc link.PacketConn, dst addr.Socksaddr) error {
	errc := make(chan error, 2)
	go func() { // 上行:客户端 datagram → 上游 UDP
		for {
			data, err := hs.ReceiveDatagram(ctx)
			if err != nil {
				errc <- err
				return
			}
			payload, ok := stripContextID(data)
			if !ok {
				continue // 非零 context-id / 畸形,按 RFC 丢弃
			}
			b := buf.New()
			if _, werr := b.Write(payload); werr != nil {
				b.Release()
				continue // 超缓冲的巨型包,丢弃而非截断发错
			}
			err = pc.WritePacket(b, dst)
			b.Release()
			if err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() { // 下行:上游 UDP → 客户端 datagram
		b := buf.New()
		defer b.Release()
		for {
			b.Reset()
			if _, err := pc.ReadPacket(b); err != nil {
				errc <- err
				return
			}
			if b.Len() > udpPayloadMax {
				continue // 超 RFC 上限,丢弃
			}
			hdr := b.ExtendHeader(1)
			hdr[0] = 0x00 // Context ID = 0
			if err := hs.SendDatagram(b.Bytes()); err != nil {
				errc <- err
				return
			}
		}
	}()
	return <-errc
}

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

// checkAuth:未配用户 = 不鉴权;配了则校验 "Basic base64(user:pass)"。
func (h *Inbound) checkAuth(header string) bool {
	if len(h.users) == 0 {
		return true
	}
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

func basicAuth(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// serverStream 把服务端接管的 *http3.Stream 抬成 link.Stream。
type serverStream struct{ s *http3.Stream }

func (s *serverStream) Read(p []byte) (int, error)     { return s.s.Read(p) }
func (s *serverStream) Write(p []byte) (int, error)    { return s.s.Write(p) }
func (s *serverStream) Close() error                   { return s.s.Close() }
func (*serverStream) LocalAddr() net.Addr              { return masqueAddr{} }
func (*serverStream) RemoteAddr() net.Addr             { return masqueAddr{} }
func (*serverStream) SetDeadline(time.Time) error      { return nil }
func (*serverStream) SetReadDeadline(time.Time) error  { return nil }
func (*serverStream) SetWriteDeadline(time.Time) error { return nil }
func (*serverStream) Unwrap() any                      { return nil }
