// Package httpupgrade 实现 HTTPUpgrade 传输层(core/transport.StreamTransport)。
//
// HTTPUpgrade = 一次 HTTP/1.1 Upgrade 握手 + 之后裸流直穿(无 WebSocket 帧/掩码)。是 WS 的
// 轻量替代,常用于过 CDN(Cloudflare 等)。线格式与 Xray / sing-box 的 httpupgrade 完全一致:
// 客户端发 `Connection: Upgrade` + `Upgrade: websocket`(但不带 Sec-WebSocket-Key),服务端
// 回 101,随后裸字节流。占 Frame band,惯用叠法 [tls, httpupgrade, vless/vmess/trojan]。
//
// 自研纯 Go 实现(net/http 只用于握手报文解析),不引重依赖 —— 符合瘦核心。
package httpupgrade

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
)

// huHandshakeTimeout 读 HTTP Upgrade 请求的最长时限(防 slow-loris 半开握手钉住 goroutine)。
const huHandshakeTimeout = 10 * time.Second

// Config 是 HTTPUpgrade 层自有配置。Path 是握手路径(默认 /);Host 是 Host 头(客户端用,
// 过 CDN 时填伪装域名;留空取连接目标)。
type Config struct {
	Path string
	Host string
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	path := n.Get("path").Str()
	if path == "" {
		path = "/"
	}
	return Config{Path: path, Host: n.Get("host").Str()}, nil
}

// Transport 是 HTTPUpgrade 传输层句柄。
type Transport struct {
	path string
	host string
}

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	path := cfg.Path
	if path == "" {
		path = "/"
	}
	return &Transport{path: path, host: cfg.Host}, nil
}

// ClientWrap 实现 StreamTransport:在下层 stream 上发 HTTP Upgrade 请求、校验 101,返回裸流。
func (t *Transport) ClientWrap(_ context.Context, below link.Stream) (link.Stream, error) {
	host := t.host
	if host == "" {
		if a := below.RemoteAddr(); a != nil {
			host = a.String()
		}
	}
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: t.path},
		Host:   host,
		Header: http.Header{},
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if err := req.Write(below); err != nil {
		return nil, err
	}
	br := bufio.NewReader(below)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(resp.Header.Get("Connection"), "upgrade") ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("httpupgrade: 服务端未回 101 Upgrade(得到 " + resp.Status + ")")
	}
	return &bufConn{Conn: below, r: br, below: below}, nil
}

// ServerWrap 实现 StreamTransport:读 HTTP Upgrade 请求、回 101,返回裸流。
func (t *Transport) ServerWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	// 传播 ctx 取消 + 防 slow-loris(同 ws):半开握手不再永久钉住 goroutine+fd。
	stop := context.AfterFunc(ctx, func() { _ = below.SetReadDeadline(time.Now()) })
	defer stop()
	_ = below.SetReadDeadline(time.Now().Add(huHandshakeTimeout))
	br := bufio.NewReader(below)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(req.Header.Get("Connection"), "upgrade") ||
		!strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("httpupgrade: 非 Upgrade 请求")
	}
	if req.Header.Get("Sec-WebSocket-Key") != "" {
		return nil, errors.New("httpupgrade: 收到真 WebSocket 请求(应走 ws 层)")
	}
	if _, err := below.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n")); err != nil {
		return nil, err
	}
	_ = below.SetReadDeadline(time.Time{}) // 握手成功,清除 deadline
	return &bufConn{Conn: below, r: br, below: below}, nil
}

// bufConn 把握手时 bufio 预读的多余字节(属于数据流)接回来:Read 走 bufio.Reader,写/关走下层。
type bufConn struct {
	net.Conn
	r     *bufio.Reader
	below any
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *bufConn) Unwrap() any                { return c.below }
