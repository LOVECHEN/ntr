// Package obfs 实现 simple-obfs 伪装(shadowsocks 的 obfs-local/obfs-server;core/transport.StreamTransport)。
// 两种模式,均自研纯 Go、线级对齐 sing-box(obfs-local)与 mihomo(transport/simple-obfs)客户端+服务端:
//
//	http(本文件):首包裹假 WebSocket-Upgrade HTTP 请求/响应(数据藏请求体),之后裸流 —— DPI 视作普通 HTTP。
//	tls(见 tls.go):首包发假 ClientHello(数据藏 session-ticket 扩展),服务端回假 ServerHello + ChangeCipherSpec,
//	                之后双向用假 application-data 记录(0x17 0x03 0x03)封装 —— DPI 视作 TLS。
//
// 占 Frame band,惯用叠法 [obfs, shadowsocks](obfs 在 SS 之下裹 TCP)。
//
//	http 客户端首写: GET http://{host}/ HTTP/1.1 + Upgrade:websocket + Sec-WebSocket-Key + Content-Length + [数据体]
//	http 服务端首响: HTTP/1.1 101 Switching Protocols + Sec-WebSocket-Accept + \r\n\r\n,随后裸流
package obfs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
)

const (
	handshakeTimeout = 10 * time.Second
	wsMagic          = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" // RFC6455 magic(算 Sec-WebSocket-Accept,拟态用)
)

// Config 是 obfs 层配置。Mode ∈ {http(默认), tls};Host 伪装域名(默认取连接目标)。
type Config struct {
	Mode string
	Host string
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	mode := n.Get("mode").Str()
	if mode == "" {
		mode = "http"
	}
	if mode != "http" && mode != "tls" {
		return Config{}, fmt.Errorf("obfs: 仅支持 mode=http|tls(得到 %q)", mode)
	}
	return Config{Mode: mode, Host: n.Get("host").Str()}, nil
}

// Transport 是 obfs 传输句柄。
type Transport struct {
	host string
	mode string
}

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = "http"
	}
	return &Transport{host: cfg.Host, mode: mode}, nil
}

// resolveHost 定伪装域名(config host 优先,否则取连接目标,再否则占位)。
func (t *Transport) resolveHost(below link.Stream) string {
	host := t.host
	if host == "" {
		if a := below.RemoteAddr(); a != nil {
			host, _, _ = net.SplitHostPort(a.String())
		}
	}
	if host == "" {
		host = "www.example.com"
	}
	return host
}

// ClientWrap 实现 StreamTransport:按 mode 返回 http 或 tls 伪装流。
func (t *Transport) ClientWrap(_ context.Context, below link.Stream) (link.Stream, error) {
	host := t.resolveHost(below)
	if t.mode == "tls" {
		return &tlsClientConn{Stream: below, server: host, firstRequest: true, firstResponse: true}, nil
	}
	return &clientConn{Stream: below, host: host, firstReq: true, firstResp: true}, nil
}

// ServerWrap 实现 StreamTransport:按 mode 分派。tls 惰性成帧(首读取 session-ticket 数据、
// 首写发 ServerHello),故直接返回;http 在此读请求 + 回 101。
func (t *Transport) ServerWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	if t.mode == "tls" {
		return &tlsServerConn{Stream: below, firstRequest: true, firstResponse: true}, nil
	}
	return t.serverWrapHTTP(ctx, below)
}

// serverWrapHTTP 是原 http 模式的服务端握手。
func (t *Transport) serverWrapHTTP(ctx context.Context, below link.Stream) (link.Stream, error) {
	stop := context.AfterFunc(ctx, func() { _ = below.SetReadDeadline(time.Now()) })
	defer stop()
	_ = below.SetReadDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReader(below)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("obfs: 非 websocket-upgrade 伪装请求")
	}
	// 取出请求体(客户端裹进来的首段数据,Content-Length 长);之后 br 指向裸上行。
	var initial []byte
	if req.Body != nil {
		initial, _ = io.ReadAll(req.Body)
	}
	_ = below.SetReadDeadline(time.Time{})
	// 回 101(Sec-WebSocket-Accept 按 RFC6455 算,纯拟态,对端不强校验)。
	accept := wsAccept(req.Header.Get("Sec-WebSocket-Key"))
	resp := "HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := below.Write([]byte(resp)); err != nil {
		return nil, err
	}
	return &serverConn{Stream: below, br: br, initial: initial}, nil
}

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsMagic))
	return base64.StdEncoding.EncodeToString(h[:])
}

// ---------- 客户端 ----------

type clientConn struct {
	link.Stream
	host      string
	firstReq  bool
	firstResp bool
	rbuf      []byte // 首读剥掉响应头后剩余的裸数据
	wmu       sync.Mutex
}

var _ link.Stream = (*clientConn)(nil)

// Write:首写把数据裹进 GET 请求体(假 websocket upgrade);之后裸写。
func (c *clientConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if !c.firstReq {
		return c.Stream.Write(b)
	}
	c.firstReq = false
	rb := make([]byte, 16)
	_, _ = rand.Read(rb)
	var h strings.Builder
	fmt.Fprintf(&h, "GET http://%s/ HTTP/1.1\r\n", c.host)
	fmt.Fprintf(&h, "Host: %s\r\n", c.host)
	h.WriteString("User-Agent: curl/7.74.0\r\n")
	h.WriteString("Upgrade: websocket\r\n")
	h.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&h, "Sec-WebSocket-Key: %s\r\n", base64.URLEncoding.EncodeToString(rb))
	fmt.Fprintf(&h, "Content-Length: %d\r\n\r\n", len(b))
	pkt := append([]byte(h.String()), b...)
	if _, err := c.Stream.Write(pkt); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read:首读剥掉服务端响应头(到 \r\n\r\n),返回其后的裸数据;之后裸读。
func (c *clientConn) Read(p []byte) (int, error) {
	if len(c.rbuf) > 0 {
		n := copy(p, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	if !c.firstResp {
		return c.Stream.Read(p)
	}
	buf := make([]byte, 4096)
	n, err := c.Stream.Read(buf)
	if err != nil {
		return 0, err
	}
	idx := bytes.Index(buf[:n], []byte("\r\n\r\n"))
	if idx == -1 {
		return 0, errors.New("obfs: 响应头无 \\r\\n\\r\\n")
	}
	c.firstResp = false
	data := buf[idx+4 : n]
	m := copy(p, data)
	if m < len(data) {
		c.rbuf = append([]byte(nil), data[m:]...)
	}
	return m, nil
}

func (c *clientConn) Unwrap() any { return c.Stream }

// ---------- 服务端 ----------

type serverConn struct {
	link.Stream
	br      *bufio.Reader
	initial []byte // 请求体里的首段数据(先于裸上行返回)
}

var _ link.Stream = (*serverConn)(nil)

func (c *serverConn) Read(p []byte) (int, error) {
	if len(c.initial) > 0 {
		n := copy(p, c.initial)
		c.initial = c.initial[n:]
		return n, nil
	}
	return c.br.Read(p) // 裸上行
}

func (c *serverConn) Unwrap() any { return c.Stream }
