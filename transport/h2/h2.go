// Package h2 实现 V2Ray 的 HTTP/2 传输(sing-box/mihomo 的 "http" network;core/transport.StreamTransport)。
//
// 单个 h2 请求全双工:客户端 PUT(默认)到 path,请求体=上行、响应体=下行;h2 天生全双工。明文走 h2c
// (prior-knowledge),叠 TLS 走 h2(ALPN)。与 sing-box transport/v2rayhttp / mihomo 线级互通。
// 与 xhttp 的区别:方法 PUT(非 POST)、无 x_padding、路径即校验点。占 Frame band,叠法 [tls, h2, vless]。
//
// 自研纯 Go(net/http + x/net/http2 的 h2c),复用 NTR 已验证的 h2-over-below 模式(同 xhttp)。
package h2

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	h2Preface        = "PRI * HTTP/2.0\r\n"
)

// Config 是 h2 传输配置。Path 握手路径(默认 /);Host 头(过 CDN 填伪装域名);Method 默认 PUT(对齐 v2ray)。
type Config struct {
	Path   string
	Host   string
	Method string
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
	method := n.Get("method").Str()
	if method == "" {
		method = http.MethodPut
	}
	return Config{Path: path, Host: n.Get("host").Str(), Method: method}, nil
}

// Transport 是 h2 传输句柄。
type Transport struct {
	path   string
	host   string
	method string
	h2c    *http2.Transport
	h2s    *http2.Server
}

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	path := cfg.Path
	if path == "" {
		path = "/"
	}
	method := cfg.Method
	if method == "" {
		method = http.MethodPut
	}
	return &Transport{
		path: path, host: cfg.Host, method: method,
		h2c: &http2.Transport{AllowHTTP: true},
		h2s: &http2.Server{},
	}, nil
}

// ClientWrap 实现 StreamTransport:h2c 上发 PUT(全双工),返回承载流的 Conn。
func (t *Transport) ClientWrap(_ context.Context, below link.Stream) (link.Stream, error) {
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
	pr, pw := io.Pipe()
	req := &http.Request{
		Method: t.method,
		URL:    &url.URL{Scheme: "https", Host: host, Path: t.path},
		Host:   host,
		Header: http.Header{},
		Body:   pr,
	}
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := cc.RoundTrip(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()
	return &clientConn{below: below, pw: pw, respCh: respCh, errCh: errCh}, nil
}

// ServerWrap 实现 StreamTransport:窥视首字节分派 —— h2 preface(PRI * HTTP/2)→ h2c ServeConn;
// 否则 → 手搓 h1.1 全双工(V2Ray http 传输明文用 h1.1,叠 TLS 才 h2;此双模覆盖两者)。
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
		return t.serveH2C(peeked)
	}
	return t.serveH1(peeked)
}

// serveH2C:h2c ServeConn 捕获唯一请求(校验 method+path),桥成 Conn。
func (t *Transport) serveH2C(below link.Stream) (link.Stream, error) {
	captured := make(chan *serverConn, 1)
	done := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !t.checkReq(r.Method, r.URL.Path) {
			http.Error(w, "bad h2 request", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		captured <- &serverConn{w: w, flusher: asFlusher(w), body: r.Body, done: done}
		<-done
	})
	go func() {
		t.h2s.ServeConn(below, &http2.ServeConnOpts{Handler: handler})
		close(captured)
	}()
	sc, ok := <-captured
	if !ok || sc == nil {
		return nil, errors.New("h2: 未捕获到有效请求")
	}
	return sc, nil
}

// serveH1:V2Ray http 明文用 h1.1 —— HTTP 请求头 + 裸双向流(非 chunked,同 httpupgrade;sing-box
// NewHTTP1Conn / mihomo 同)。读请求头 → 回裸 200 → peekConn 即裸流(Read 走 br 取上行、Write 走 below 发下行)。
func (t *Transport) serveH1(below *peekConn) (link.Stream, error) {
	_ = below.SetReadDeadline(time.Now().Add(handshakeTimeout))
	req, err := http.ReadRequest(below.br)
	if err != nil {
		return nil, err
	}
	_ = below.SetReadDeadline(time.Time{})
	if !t.checkReq(req.Method, req.URL.Path) {
		return nil, errors.New("h2: 方法/路径不匹配")
	}
	// ★不触碰 req.Body:sing-box/mihomo 的 h1 请求无体框架(裸上行在 br 上,紧随头之后),
	// ReadRequest 后 br 恰好指向裸上行;读 req.Body 反而会吞掉裸上行。
	if _, err := below.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		return nil, err
	}
	return below, nil // peekConn:Read=br(裸上行),Write/Close=below(裸下行)
}

// checkReq 校验方法(若配置)+ 路径前缀。
func (t *Transport) checkReq(method, path string) bool {
	if t.method != "" && method != t.method {
		return false
	}
	return strings.HasPrefix(path, strings.TrimSuffix(t.path, "/"))
}

func asFlusher(w http.ResponseWriter) http.Flusher {
	if f, ok := w.(http.Flusher); ok {
		return f
	}
	return nil
}

// ---------- 客户端 Conn ----------

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
				c.rerr = fmt.Errorf("h2: 服务端回 %s(期望 200)", resp.Status)
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

// ---------- 服务端 Conn ----------

// serverConn 是 h2c 路径的承载流(h1.1 路径直接返回裸 peekConn,不经此)。写响应体=下行,读请求体=上行。
type serverConn struct {
	w       http.ResponseWriter
	flusher http.Flusher
	done    chan struct{}
	body    io.ReadCloser
	once    sync.Once
}

var _ link.Stream = (*serverConn)(nil)

func (c *serverConn) Read(p []byte) (int, error) { return c.body.Read(p) }
func (c *serverConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err == nil && c.flusher != nil {
		c.flusher.Flush()
	}
	return n, err
}
func (c *serverConn) Close() error {
	c.once.Do(func() {
		_ = c.body.Close()
		close(c.done) // 解阻塞 h2c handler,ServeConn 收尾该 stream
	})
	return nil
}
func (c *serverConn) LocalAddr() net.Addr              { return dummyAddr("h2") }
func (c *serverConn) RemoteAddr() net.Addr             { return dummyAddr("h2") }
func (c *serverConn) SetDeadline(time.Time) error      { return nil }
func (c *serverConn) SetReadDeadline(time.Time) error  { return nil }
func (c *serverConn) SetWriteDeadline(time.Time) error { return nil }
func (c *serverConn) Unwrap() any                      { return nil }

type dummyAddr string

func (dummyAddr) Network() string  { return "h2" }
func (d dummyAddr) String() string { return string(d) }

// peekConn 把窥视用的 bufio 接回读路径。
type peekConn struct {
	link.Stream
	br *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.br.Read(p) }
func (c *peekConn) Unwrap() any                { return c.Stream }
