// Package naive 把 NaiveProxy 接入 NTR:客户端出站 + 服务端入站。
//
// NaiveProxy 是 HTTP/2 CONNECT 代理 + 前 8 包随机填充(抗流量分析),线格式与 sing-box 的
// naive 实现一致(padding 帧 [2B BE 数据长][1B padding 长][data][padding],Padding 头必填,
// Basic 认证)。本实现按该线格式自写,复用 x/net/http2(NTR 已有),零新依赖。
//
// 会话式:一条 TLS+H2 连接多路复用多条 CONNECT 流,故走 endpoint.Outbound + InboundHandler,
// 不套 NTR 流式栈。TLS 自建(ALPN h2)。
package naive

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

// Options 是 NaiveProxy 出站配置。
type Options struct {
	Server      string // 上游 host:port
	User        string
	Password    string
	SNI         string
	Insecure    bool
	Fingerprint string // uTLS 客户端指纹(chrome/firefox/safari/ios/edge/random;空=标准 crypto/tls)
}

// Outbound 是 NaiveProxy 出站:惰性建一条 TLS+H2 连接,DialStream 在其上开一条带填充的 CONNECT 流。
type Outbound struct {
	server      string
	tlsConfig   *cryptotls.Config
	authHeader  string
	fingerprint string
	tr          *http2.Transport
	mu          sync.Mutex
	cc          *http2.ClientConn
}

// NewOutbound 构造 NaiveProxy 出站。
func NewOutbound(o Options) (*Outbound, error) {
	if o.Server == "" {
		return nil, errors.New("naive: server 为空")
	}
	return &Outbound{
		server:      o.Server,
		tlsConfig:   &cryptotls.Config{ServerName: o.SNI, InsecureSkipVerify: o.Insecure, NextProtos: []string{"h2"}, MinVersion: cryptotls.VersionTLS12},
		authHeader:  "Basic " + base64.StdEncoding.EncodeToString([]byte(o.User+":"+o.Password)),
		fingerprint: o.Fingerprint,
		tr:          &http2.Transport{},
	}, nil
}

// DialStream 在 H2 连接上开一条到 dst 的 CONNECT 流(带 Padding 头),收 200 后成带填充的双向流。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	st, err := o.connect(ctx, dst.String())
	if err != nil {
		o.dropDeadConn()
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
			"Proxy-Authorization": []string{o.authHeader},
			"Padding":             []string{generatePaddingHeader()},
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
		return nil, errors.New("naive: 服务端非 200(" + resp.Status + ")")
	}
	if resp.Header.Get("Padding") == "" {
		_ = resp.Body.Close()
		_ = pw.Close()
		return nil, errors.New("naive: 服务端响应缺 Padding 头(不是 naive 服务端?)")
	}
	return &paddedStream{r: resp.Body, w: pw, closeFn: func() error { _ = pw.Close(); return resp.Body.Close() }}, nil
}

// DialPacket:NaiveProxy 无 UDP(仅 CONNECT TCP 隧道)。
func (o *Outbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, errors.New("naive: UDP not supported")
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

// dropDeadConn 清掉已不可用的 H2 连接,使下次重建。
func (o *Outbound) dropDeadConn() {
	o.mu.Lock()
	if o.cc != nil && !o.cc.CanTakeNewRequest() {
		o.cc = nil
	}
	o.mu.Unlock()
}

// paddedStream 把一条带 naive 填充的 H2 流(读写端分离)抬成 link.Stream。
type paddedStream struct {
	r       io.Reader
	w       io.Writer
	flush   func()
	closeFn func() error
	pad     paddingConn
	rmu     sync.Mutex
	wmu     sync.Mutex
	once    sync.Once
	cerr    error
}

func (s *paddedStream) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	return s.pad.read(s.r, p)
}

func (s *paddedStream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	n, err := s.pad.write(s.w, p)
	if err == nil && s.flush != nil {
		s.flush()
	}
	return n, err
}

func (s *paddedStream) Close() error {
	s.once.Do(func() { s.cerr = s.closeFn() })
	return s.cerr
}

func (*paddedStream) LocalAddr() net.Addr              { return naiveAddr{} }
func (*paddedStream) RemoteAddr() net.Addr             { return naiveAddr{} }
func (*paddedStream) SetDeadline(time.Time) error      { return nil }
func (*paddedStream) SetReadDeadline(time.Time) error  { return nil }
func (*paddedStream) SetWriteDeadline(time.Time) error { return nil }
func (*paddedStream) Unwrap() any                      { return nil }

type naiveAddr struct{}

func (naiveAddr) Network() string { return "naive" }
func (naiveAddr) String() string  { return "naive-h2" }
