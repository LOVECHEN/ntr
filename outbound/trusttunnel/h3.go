package trusttunnel

import (
	"context"
	"errors"
	"net"
	neturl "net/url"
	"sync"
	"time"

	mhttp "github.com/metacubex/http"
	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	mtls "github.com/metacubex/tls"

	"github.com/LOVECHEN/ntr/core/link"
)

// TrustTunnel over HTTP/3(QUIC):与 H2 同一语义 —— 普通 CONNECT(:authority = 目标 / _udp2 / _check),
// 回 200 后请求流即双向字节流(_udp2 时其上是长度前缀帧)。对齐 TrustTunnel 规范 / mihomo transport/trusttunnel
// (出站 quic: true;服务端与 H2 同端口另开 UDP 监听)。

// h3Client 是 H3 出站:惰性建一条 QUIC + H3 连接,每次 CONNECT 开一条请求流。
type h3Client struct {
	server     string
	tlsConfig  *mtls.Config
	quicConfig *quic.Config
	tr         *http3.Transport

	mu sync.Mutex
	pc net.PacketConn
	qc *quic.Conn
	cc *http3.ClientConn
}

func newH3Client(server, sni string, insecure bool) *h3Client {
	return &h3Client{
		server:     server,
		tlsConfig:  &mtls.Config{ServerName: sni, InsecureSkipVerify: insecure, NextProtos: []string{http3.NextProtoH3}},
		quicConfig: &quic.Config{MaxIdleTimeout: 2 * 37 * time.Second, KeepAlivePeriod: 10 * time.Second},
		tr:         &http3.Transport{},
	}
}

func (c *h3Client) getConn(ctx context.Context) (*http3.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc != nil && c.qc != nil && c.qc.Context().Err() == nil {
		return c.cc, nil
	}
	c.closeLocked()
	udpAddr, err := net.ResolveUDPAddr("udp", c.server)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	qc, err := quic.Dial(ctx, pc, udpAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	c.pc, c.qc, c.cc = pc, qc, c.tr.NewClientConn(qc)
	return c.cc, nil
}

func (c *h3Client) closeLocked() {
	if c.qc != nil {
		_ = c.qc.CloseWithError(0, "")
	}
	if c.pc != nil {
		_ = c.pc.Close()
	}
	c.pc, c.qc, c.cc = nil, nil, nil
}

func (c *h3Client) reset() {
	c.mu.Lock()
	c.closeLocked()
	c.mu.Unlock()
}

// connect 发一条普通 CONNECT(:authority = authority),收 2xx 后交出请求流。
func (c *h3Client) connect(ctx context.Context, authority, auth, userAgent string) (link.Stream, error) {
	cc, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	hdr := mhttp.Header{}
	hdr.Set("Proxy-Authorization", auth)
	hdr.Set("User-Agent", userAgent)
	if err := rs.SendRequestHeader(&mhttp.Request{
		Method: mhttp.MethodConnect,
		URL:    &neturl.URL{Host: authority},
		Host:   authority,
		Header: hdr,
	}); err != nil {
		_ = rs.Close()
		return nil, err
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		_ = rs.Close()
		return nil, err
	}
	if resp.StatusCode != mhttp.StatusOK {
		_ = rs.Close()
		return nil, errors.New("trusttunnel: h3 服务端非 200(" + resp.Status + ")")
	}
	return &h3ClientStream{rs: rs}, nil
}

type h3ClientStream struct{ rs *http3.RequestStream }

func (s *h3ClientStream) Read(p []byte) (int, error)  { return s.rs.Read(p) }
func (s *h3ClientStream) Write(p []byte) (int, error) { return s.rs.Write(p) }
func (s *h3ClientStream) Close() error {
	s.rs.CancelRead(0)
	return s.rs.Close()
}
func (*h3ClientStream) LocalAddr() net.Addr              { return ttAddr{} }
func (*h3ClientStream) RemoteAddr() net.Addr             { return ttAddr{} }
func (*h3ClientStream) SetDeadline(time.Time) error      { return nil }
func (*h3ClientStream) SetReadDeadline(time.Time) error  { return nil }
func (*h3ClientStream) SetWriteDeadline(time.Time) error { return nil }
func (*h3ClientStream) Unwrap() any                      { return nil }

// ---------- 服务端:与 H2 同端口另开 UDP 跑 H3 ----------

// EnableH3 开启 H3 服务端(用 metacubex TLS;证书应与 H2 侧同一张)。开启后运行时会在入站同址另开 UDP 监听
// 并调 ServePacket。
func (h *Inbound) EnableH3(tlsConfig *mtls.Config) { h.h3TLS = tlsConfig }

// SupportsNativePacket 报是否需要同址 UDP 监听(开了 H3 才要)。
func (h *Inbound) SupportsNativePacket() bool { return h.h3TLS != nil }

// ServePacket 在运行时给的 UDP socket 上跑 H3 服务端,阻塞至 ctx 取消。
func (h *Inbound) ServePacket(ctx context.Context, pc net.PacketConn) error {
	srv := &http3.Server{
		TLSConfig: http3.ConfigureTLSConfig(h.h3TLS),
		Handler:   mhttp.HandlerFunc(func(w mhttp.ResponseWriter, r *mhttp.Request) { h.serveH3(r.Context(), w, r) }),
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err := srv.Serve(pc)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// serveH3 把一条 H3 请求适配成协议无关的 tunnelReq 交 handle(与 H2 共用同一份 CONNECT 语义)。
func (h *Inbound) serveH3(ctx context.Context, w mhttp.ResponseWriter, r *mhttp.Request) {
	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}
	remote := remoteAddr(r.RemoteAddr)
	h.handle(ctx, tunnelReq{
		method: r.Method,
		host:   host,
		auth:   r.Header.Get("Proxy-Authorization"),
		remote: remote,
		reject: func(code int, msg string) { mhttp.Error(w, msg, code) },
		accept: func() (link.Stream, error) {
			streamer, ok := w.(http3.HTTPStreamer)
			if !ok {
				mhttp.Error(w, "no hijack", mhttp.StatusInternalServerError)
				return nil, errors.New("trusttunnel: h3 无法接管流")
			}
			w.WriteHeader(mhttp.StatusOK)
			return &h3ServerStream{s: streamer.HTTPStream(), remote: remote}, nil
		},
	})
}

type h3ServerStream struct {
	s      *http3.Stream
	remote net.Addr
}

func (s *h3ServerStream) Read(p []byte) (int, error)  { return s.s.Read(p) }
func (s *h3ServerStream) Write(p []byte) (int, error) { return s.s.Write(p) }
func (s *h3ServerStream) Close() error {
	s.s.CancelRead(0)
	return s.s.Close()
}
func (*h3ServerStream) LocalAddr() net.Addr              { return ttAddr{} }
func (s *h3ServerStream) RemoteAddr() net.Addr           { return s.remote }
func (*h3ServerStream) SetDeadline(time.Time) error      { return nil }
func (*h3ServerStream) SetReadDeadline(time.Time) error  { return nil }
func (*h3ServerStream) SetWriteDeadline(time.Time) error { return nil }
func (*h3ServerStream) Unwrap() any                      { return nil }
