// Package httpproxy 实现 HTTP 代理协议(CONNECT 隧道 + 明文转发),接入 NTR 统一协议插件契约。
//
// 作为 proxy.Server:本地入站(浏览器/curl 的 http 代理)。CONNECT host:port → 回 200 后裸隧道;
// 明文 absolute-form 请求(GET http://.../)→ 改写成 origin-form 转发到目标。无鉴权 → Ambient。
// 作为 proxy.Client:出站链到上游 HTTP 代理(发 CONNECT、校验 200)。
//
// 自研纯 Go(net/http 仅解析握手报文)。Band=Proxy,可裸跑(明文 http 代理)或叠 [tls, http]。
package httpproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/spec"
)

var (
	_ proxy.Server = (*Proxy)(nil)
	_ proxy.Client = (*Proxy)(nil)
)

// Config 是 HTTP 代理配置(当前无自有参数,鉴权走外部 Authenticator / 无鉴权)。
type Config struct{}

// Parse:HTTP 代理无自有线上参数。
func Parse(*spec.Node) (Config, error) { return Config{}, nil }

// Proxy 是 HTTP 代理连接级句柄(无状态)。
type Proxy struct{}

// Build 构造 Proxy。
func Build(_ context.Context, _ Config, _ any) (any, error) { return &Proxy{}, nil }

// ServerHandshake 实现 proxy.Server:解析首个 HTTP 请求(CONNECT 或明文转发),返回承载流 + 目标。
func (p *Proxy) ServerHandshake(_ context.Context, below link.Stream, _ proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	br := bufio.NewReader(below)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Del("Proxy-Connection")

	if req.Method == http.MethodConnect {
		dst, err := parseHostPort(req.Host, 443)
		if err != nil {
			return nil, nil, err
		}
		if _, err := below.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return nil, nil, err
		}
		req := &proxy.Request{Cred: cred.Ref{ID: cred.Ambient}, Network: endpoint.NetworkTCP, Dst: dst}
		return &bufStream{Conn: below, r: br, below: below}, req, nil
	}

	// 明文转发:客户端发 absolute-form(GET http://host/path)。改写成 origin-form 交下游转发到目标。
	if req.URL == nil || req.URL.Host == "" {
		return nil, nil, errors.New("httpproxy: 非代理请求(缺 absolute-form URL)")
	}
	host := req.URL.Host
	dst, err := parseHostPort(host, 80)
	if err != nil {
		return nil, nil, err
	}
	// 重建 origin-form 请求(清 scheme/host,request-target 只留 path)。用 io.Pipe 流式 req.Write:
	// 头 + body 边写边被下游读走,不把整个 body 缓进内存(防超大 POST 撑爆);req.Write 负责正确
	// 序列化(Content-Length/chunked/Host 头等)。body 从 br 惰性读,读完 pipe EOF → 该方向结束。
	if req.Host == "" {
		req.Host = host
	}
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.RequestURI = ""
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(req.Write(pw)) }()
	preq := &proxy.Request{Cred: cred.Ref{ID: cred.Ambient}, Network: endpoint.NetworkTCP, Dst: dst}
	return &forwardStream{Conn: below, pr: pr, up: pr, r: br, below: below}, preq, nil
}

// ClientHandshake 实现 proxy.Client:向上游 HTTP 代理发 CONNECT,校验 200,返回裸隧道。
func (p *Proxy) ClientHandshake(_ context.Context, below link.Stream, _ []byte, dst addr.Socksaddr) (link.Stream, error) {
	target := dst.String()
	if _, err := fmt.Fprintf(below, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return nil, err
	}
	br := bufio.NewReader(below)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpproxy: 上游 CONNECT 回 %s", resp.Status)
	}
	return &bufStream{Conn: below, r: br, below: below}, nil
}

// parseHostPort 把 "host:port" / "host"(无端口用默认)解析成 Socksaddr。
func parseHostPort(s string, defPort uint16) (addr.Socksaddr, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		host = s // 无端口
		portStr = ""
	}
	port := defPort
	if portStr != "" {
		n, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return addr.Socksaddr{}, fmt.Errorf("httpproxy: 端口无效 %q", portStr)
		}
		port = uint16(n)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return addr.Socksaddr{Addr: ip, Port: port}, nil
	}
	return addr.Socksaddr{Fqdn: host, Port: port}, nil
}

// bufStream:CONNECT 隧道 / 客户端隧道,Read 走 bufio(接回握手预读),写关走下层。
type bufStream struct {
	net.Conn
	r     *bufio.Reader
	below any
}

func (s *bufStream) Read(p []byte) (int, error) { return s.r.Read(p) }
func (s *bufStream) Unwrap() any                { return s.below }

// forwardStream:明文转发,Read 先流式吐重建的请求(up=pipe,req.Write 边写边读走,不缓 body),
// 请求写完(pipe EOF)后转读 br 的后续客户端字节 —— 保持该方向不提前 EOF,让响应能回流。
type forwardStream struct {
	net.Conn
	pr    *io.PipeReader // pipe 读端(Close 时关它,解阻塞 req.Write goroutine 防泄漏;不可变)
	up    io.Reader      // 读游标:先 pipe(流式重建请求),EOF 后置 nil 转读 r
	r     *bufio.Reader  // 请求之后的后续客户端字节(req.Write 已顺序读完 body,故与其不冲突)
	below any
}

func (s *forwardStream) Read(p []byte) (int, error) {
	if s.up != nil {
		n, err := s.up.Read(p)
		if err == io.EOF {
			s.up = nil // 请求已完整发出 → 之后读 br
			if n > 0 {
				return n, nil
			}
			return s.r.Read(p)
		}
		return n, err
	}
	return s.r.Read(p)
}

// Close 关 pipe 读端(让 req.Write 的 pw.Write 返回 ErrClosedPipe,goroutine 退出),再关下层。
// 若相关方向从未被中继(如出站拨号失败即拆链),这是防 req.Write goroutine 永久阻塞的关键。
func (s *forwardStream) Close() error {
	s.pr.Close()
	return s.Conn.Close()
}
func (s *forwardStream) Unwrap() any { return s.below }
