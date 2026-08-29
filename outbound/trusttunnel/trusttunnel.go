// Package trusttunnel 把 TrustTunnel 接入 NTR:客户端出站 + 服务端入站。
//
// TrustTunnel 是 AdGuard VPN 开源的抗审查 VPN 协议(github.com/TrustTunnel/TrustTunnel,
// 公开 PROTOCOL.md):把 TCP/UDP/ICMP 封进加密的 HTTP/2 或 HTTP/3,流量与普通 HTTPS 不可区分。
// 本实现按 spec 自写(H2 + TCP CONNECT MVP;h3 与 UDP/_udp2 后置),互通对端可用 mihomo 官方实现。
//
// 会话式:一条 TLS+H2 连接多路复用多条 CONNECT 流,故走 endpoint.Outbound(客户端开 CONNECT 流)
// + InboundHandler(服务端 h2 CONNECT 解复用),不套 NTR 流式栈。TLS 自建(ALPN h2),认证 Basic。
package trusttunnel

import (
	"context"
	cryptotls "crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/internal/utlsfp"
)

var _ endpoint.Outbound = (*Outbound)(nil)

// Options 是 TrustTunnel 出站配置。
type Options struct {
	Server      string // 上游 host:port
	User        string
	Password    string
	SNI         string
	Insecure    bool
	Fingerprint string // uTLS 客户端指纹(chrome/firefox/safari/ios/edge/random;空=标准 crypto/tls)
}

// Outbound 是 TrustTunnel 出站:惰性建一条 TLS+H2 连接,DialStream 在其上开一条 CONNECT 流;
// H2 连接不可用(GOAWAY/断)时下次自动重建。
type Outbound struct {
	server      string
	tlsConfig   *cryptotls.Config
	authHeader  string
	fingerprint string
	tr          *http2.Transport
	mu          sync.Mutex
	cc          *http2.ClientConn
}

// NewOutbound 构造 TrustTunnel 出站。
func NewOutbound(o Options) (*Outbound, error) {
	if o.Server == "" {
		return nil, errors.New("trusttunnel: server 为空")
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(o.User+":"+o.Password))
	return &Outbound{
		server:      o.Server,
		tlsConfig:   &cryptotls.Config{ServerName: o.SNI, InsecureSkipVerify: o.Insecure, NextProtos: []string{"h2"}, MinVersion: cryptotls.VersionTLS12},
		authHeader:  auth,
		fingerprint: o.Fingerprint,
		tr:          &http2.Transport{},
	}, nil
}

// DialStream 在 H2 连接上开一条到 dst 的 CONNECT 流(收 200 后成裸双向字节流)。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	st, err := o.connect(ctx, dst.String())
	if err != nil {
		o.reset(nil)
		st, err = o.connect(ctx, dst.String())
	}
	return st, err
}

func (o *Outbound) connect(ctx context.Context, authority string) (link.Stream, error) {
	cc, err := o.getConn(ctx)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	req := (&http.Request{
		Method: http.MethodConnect,
		URL:    &neturl.URL{Host: authority},
		Host:   authority,
		Header: http.Header{
			"proxy-authorization": []string{o.authHeader},
			"user-agent":          []string{"ntr trusttunnel"},
		},
		Body: pr,
	}).WithContext(ctx)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		return nil, errors.New("trusttunnel: 服务端非 200(" + resp.Status + ")")
	}
	return &h2Stream{r: resp.Body, w: pw, closeFn: func() error { _ = pw.Close(); return resp.Body.Close() }}, nil
}

// DialPacket:TrustTunnel UDP(_udp2 帧复用)待接入。
func (o *Outbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, errors.New("trusttunnel: UDP (_udp2) not implemented yet")
}

// getConn 返回复用的 H2 ClientConn,首次或不可用时惰性 TLS 建连。
func (o *Outbound) getConn(ctx context.Context) (*http2.ClientConn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cc != nil && o.cc.CanTakeNewRequest() {
		return o.cc, nil
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", o.server)
	if err != nil {
		return nil, err
	}
	tc, err := utlsfp.Dial(ctx, raw, o.tlsConfig, o.fingerprint)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	cc, err := o.tr.NewClientConn(tc)
	if err != nil {
		_ = tc.Close()
		return nil, err
	}
	o.cc = cc
	return cc, nil
}

func (o *Outbound) reset(_ *http2.ClientConn) {
	o.mu.Lock()
	if o.cc != nil && !o.cc.CanTakeNewRequest() {
		o.cc = nil
	}
	o.mu.Unlock()
}

// h2Stream 把一条 H2 CONNECT 流(读端 + 写端分离)抬成 link.Stream(net.Conn)。
type h2Stream struct {
	r       io.Reader
	w       io.Writer
	closeFn func() error
	once    sync.Once
	cerr    error
}

func (s *h2Stream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *h2Stream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *h2Stream) Close() error {
	s.once.Do(func() { s.cerr = s.closeFn() })
	return s.cerr
}
func (*h2Stream) LocalAddr() net.Addr              { return ttAddr{} }
func (*h2Stream) RemoteAddr() net.Addr             { return ttAddr{} }
func (*h2Stream) SetDeadline(time.Time) error      { return nil }
func (*h2Stream) SetReadDeadline(time.Time) error  { return nil }
func (*h2Stream) SetWriteDeadline(time.Time) error { return nil }
func (*h2Stream) Unwrap() any                      { return nil }

type ttAddr struct{}

func (ttAddr) Network() string { return "trusttunnel" }
func (ttAddr) String() string  { return "trusttunnel-h2" }
