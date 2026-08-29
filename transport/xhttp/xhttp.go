// Package xhttp 实现 Xray XHTTP(SplitHTTP)传输层的 stream-one 模式(core/transport.StreamTransport)。
//
// XHTTP 有三种模式:packet-up / stream-up / stream-one。前两者需多连接、破坏 NTR「一连接=一流」模型;
// 唯 stream-one 是【单请求全双工】(请求体=上行、响应体=下行),契合 StreamTransport(包单条 below)。
//
// ★关键:stream-one 必须【HTTP/2(h2c 明文)】才能真正全双工 —— Go 的 HTTP/1.1 服务端默认半双工
// (响应前先 drain 请求体,实测 client 保持 body 开放即死锁),而 xray 服务端用标准 http.Server 未开
// EnableFullDuplex,故 h1.1 走不通;xray 服务端 SetUnencryptedHTTP2(true) 接受 h2c,h2 天生全双工。
// 因此本端【客户端恒用 h2c】。服务端【双模】:窥视首字节,h2 preface(PRI * HTTP/2)→ h2c ServeConn;
// 否则 → 手搓 h1.1 全双工(兼容发 h1.1 的对端客户端)。
//
// 线格式对齐 xray-core transport/internet/splithttp(实测抓包 + 读源码,不臆测):
//   POST {path}/ ;  Referer: http://{host}{path}/?x_padding=XXX…(padding 放 Referer 的 x_padding query);
//   请求体=上行、响应体=下行(h2 DATA 帧,或 h1.1 chunked)。padding 服务端校验非空且长度在范围(默认 100-1000)。
// 占 Frame band,惯用叠法 [tls, xhttp, vless]。自研纯 Go(net/http + x/net/http2)。
package xhttp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
)

const (
	handshakeTimeout = 10 * time.Second
	paddingLen       = 200 // ∈ xray 默认 [100,1000];客户端发的 x_padding 长度
	h2Preface        = "PRI * HTTP/2.0\r\n"
)

// Config 是 XHTTP 层自有配置。
type Config struct {
	Path string
	Host string
	Mode string
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	path := n.Get("path").Str()
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	mode := n.Get("mode").Str()
	if mode == "" {
		mode = "stream-one"
	}
	if mode != "stream-one" {
		return Config{}, fmt.Errorf("xhttp: 暂只支持 mode=stream-one(得到 %q)", mode)
	}
	return Config{Path: path, Host: n.Get("host").Str(), Mode: mode}, nil
}

// Transport 是 XHTTP 传输层句柄。path 归一化为以 / 结尾(与 xray 一致)。
type Transport struct {
	path string
	host string
	h2c  *http2.Transport
	h2s  *http2.Server
}

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	path := cfg.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return &Transport{
		path: path,
		host: cfg.Host,
		h2c:  &http2.Transport{AllowHTTP: true}, // h2c:明文 HTTP/2
		h2s:  &http2.Server{},
	}, nil
}

// ---------- 客户端(h2c,全双工)----------

// ClientWrap 实现 StreamTransport:在 below 上跑 h2c,发 stream-one POST(全双工),返回承载流的 Conn。
func (t *Transport) ClientWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	host := t.host
	if host == "" {
		if a := below.RemoteAddr(); a != nil {
			host = a.String()
		}
	}
	cc, err := t.h2c.NewClientConn(below)
	if err != nil {
		return nil, err
	}
	pad := strings.Repeat("X", paddingLen)
	referer := "http://" + host + t.path + "?x_padding=" + pad

	pr, pw := io.Pipe() // 上行:Conn.Write → pw → 请求体
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Scheme: "https", Host: host, Path: t.path},
		Host:   host,
		Header: http.Header{
			"User-Agent":   {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"},
			"Accept":       {"*/*"},
			"Content-Type": {"application/grpc"},
			"Referer":      {referer},
		},
		Body: pr,
	}

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := cc.RoundTrip(req) // h2 全双工:发请求同时可读响应
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	c := &clientConn{below: below, pw: pw, respCh: respCh, errCh: errCh}
	return c, nil
}

// clientConn:写=上行(pipe→请求体),读=下行(响应体)。h2 原生全双工。
type clientConn struct {
	below  link.Stream
	pw     *io.PipeWriter
	respCh chan *http.Response
	errCh  chan error
	body   io.ReadCloser
	once   sync.Once
	rerr   error
}

var _ link.Stream = (*clientConn)(nil)

func (c *clientConn) ensureResp() error {
	c.once.Do(func() {
		select {
		case resp := <-c.respCh:
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				c.rerr = fmt.Errorf("xhttp: 服务端回 %s(期望 200)", resp.Status)
				return
			}
			c.body = resp.Body
		case err := <-c.errCh:
			c.rerr = err
		}
	})
	return c.rerr
}

func (c *clientConn) Read(p []byte) (int, error) {
	if err := c.ensureResp(); err != nil {
		return 0, err
	}
	return c.body.Read(p)
}
func (c *clientConn) Write(p []byte) (int, error) { return c.pw.Write(p) }
func (c *clientConn) Close() error {
	_ = c.pw.Close()
	if c.body != nil {
		_ = c.body.Close()
	}
	return c.below.Close()
}
func (c *clientConn) LocalAddr() net.Addr                { return c.below.LocalAddr() }
func (c *clientConn) RemoteAddr() net.Addr               { return c.below.RemoteAddr() }
func (c *clientConn) SetDeadline(t time.Time) error      { return c.below.SetDeadline(t) }
func (c *clientConn) SetReadDeadline(t time.Time) error  { return c.below.SetReadDeadline(t) }
func (c *clientConn) SetWriteDeadline(t time.Time) error { return c.below.SetWriteDeadline(t) }
func (c *clientConn) Unwrap() any                        { return c.below }

// ---------- 服务端(双模:h2c ServeConn / 手搓 h1.1 全双工)----------

// ServerWrap 实现 StreamTransport:窥视首字节分派 h2c 或 h1.1,均全双工,返回承载流的 Conn。
func (t *Transport) ServerWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	_ = below.SetReadDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReader(below)
	head, err := br.Peek(len(h2Preface))
	if err != nil {
		return nil, err
	}
	_ = below.SetReadDeadline(time.Time{})
	peeked := &peekConn{Stream: below, br: br}
	if string(head) == h2Preface {
		return t.serveH2C(ctx, peeked)
	}
	return t.serveH1(ctx, peeked)
}

// serveH2C:在 below 上跑 h2 server,捕获唯一的 stream-one 请求,桥成 Conn。
func (t *Transport) serveH2C(ctx context.Context, below link.Stream) (link.Stream, error) {
	captured := make(chan *serverConn, 1)
	done := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc, ok := t.acceptRequest(w, r, done)
		if !ok {
			return
		}
		captured <- sc
		<-done // 阻塞 handler 保持 h2 stream 开放,直到 Conn 关闭
	})
	go func() {
		t.h2s.ServeConn(below, &http2.ServeConnOpts{Handler: handler})
		close(captured) // ServeConn 退出(连接断)→ 若还没捕获则解阻塞 ServerWrap
	}()
	sc, ok := <-captured
	if !ok || sc == nil {
		return nil, errors.New("xhttp: h2c 未捕获到有效 stream-one 请求")
	}
	return sc, nil
}

// serveH1:手搓 h1.1 全双工(Go 标准 server 半双工,故不能用 http.Server)。
func (t *Transport) serveH1(ctx context.Context, below link.Stream) (link.Stream, error) {
	_ = below.SetReadDeadline(time.Now().Add(handshakeTimeout))
	req, err := http.ReadRequest(below.(*peekConn).br)
	if err != nil {
		return nil, err
	}
	_ = below.SetReadDeadline(time.Time{})
	if req.Method != http.MethodPost {
		return nil, errors.New("xhttp: stream-one 需 POST")
	}
	base := strings.TrimSuffix(t.path, "/")
	if !strings.HasPrefix(req.URL.Path, base) {
		return nil, errors.New("xhttp: 路径不匹配")
	}
	if !validPadding(req) {
		return nil, errors.New("xhttp: 缺 x_padding")
	}
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\nX-Accel-Buffering: no\r\nCache-Control: no-store\r\n\r\n"
	if _, err := below.Write([]byte(resp)); err != nil {
		return nil, err
	}
	return &serverConn{below: below, cw: httputil.NewChunkedWriter(below), body: req.Body}, nil
}

// acceptRequest 校验 stream-one 请求(路径/方法/padding),回 200,返回 serverConn。
func (t *Transport) acceptRequest(w http.ResponseWriter, r *http.Request, done chan struct{}) (*serverConn, bool) {
	base := strings.TrimSuffix(t.path, "/")
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, base) || !validPadding(r) {
		http.Error(w, "bad xhttp request", http.StatusBadRequest)
		return nil, false
	}
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return &serverConn{w: w, flusher: asFlusher(w), body: r.Body, done: done}, true
}

// validPadding 从 Referer 的 x_padding 或 URL 的 x_padding 取 padding,非空即认(从宽,最大化互通)。
func validPadding(req *http.Request) bool {
	if ref := req.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Query().Get("x_padding") != "" {
			return true
		}
	}
	return req.URL.Query().Get("x_padding") != ""
}

func asFlusher(w http.ResponseWriter) http.Flusher {
	if f, ok := w.(http.Flusher); ok {
		return f
	}
	return nil
}

// serverConn:读=上行(请求体),写=下行。h2c 用 ResponseWriter+Flush;h1.1 用 chunked writer。
type serverConn struct {
	// h1.1 路径
	below link.Stream
	cw    io.Writer
	// h2c 路径
	w       http.ResponseWriter
	flusher http.Flusher
	done    chan struct{}
	// 共用
	body io.ReadCloser
	once sync.Once
}

var _ link.Stream = (*serverConn)(nil)

func (c *serverConn) Read(p []byte) (int, error) { return c.body.Read(p) }
func (c *serverConn) Write(p []byte) (int, error) {
	if c.w != nil { // h2c
		n, err := c.w.Write(p)
		if err == nil && c.flusher != nil {
			c.flusher.Flush()
		}
		return n, err
	}
	return c.cw.Write(p) // h1.1
}
func (c *serverConn) Close() error {
	c.once.Do(func() {
		_ = c.body.Close()
		if c.done != nil { // h2c:解阻塞 handler,ServeConn 收尾该 stream
			close(c.done)
		}
		if wc, ok := c.cw.(io.Closer); ok {
			_ = wc.Close()
		}
		if c.below != nil {
			_ = c.below.Close()
		}
	})
	return nil
}
func (c *serverConn) LocalAddr() net.Addr  { return dummyAddr("xhttp") }
func (c *serverConn) RemoteAddr() net.Addr { return dummyAddr("xhttp") }
func (c *serverConn) SetDeadline(time.Time) error {
	if c.below != nil {
		return nil
	}
	return nil
}
func (c *serverConn) SetReadDeadline(time.Time) error  { return nil }
func (c *serverConn) SetWriteDeadline(time.Time) error { return nil }
func (c *serverConn) Unwrap() any                      { return nil }

type dummyAddr string

func (dummyAddr) Network() string  { return "xhttp" }
func (d dummyAddr) String() string { return string(d) }

// peekConn 把窥视用的 bufio 接回读路径。
type peekConn struct {
	link.Stream
	br *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.br.Read(p) }
func (c *peekConn) Unwrap() any                { return c.Stream }
