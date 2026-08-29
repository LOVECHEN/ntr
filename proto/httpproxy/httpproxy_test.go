package httpproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
)

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

// TestConnectRoundTrip:客户端 ClientHandshake 发 CONNECT ↔ 服务端 ServerHandshake 解出目标,
// 200 后裸隧道双向直穿。
func TestConnectRoundTrip(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()
	dst := addr.FromFqdn("target.example", 8443)

	errc := make(chan error, 1)
	go func() {
		p := &Proxy{}
		cs, err := p.ClientHandshake(ctx, pipeStream{c}, nil, dst)
		if err != nil {
			errc <- err
			return
		}
		if _, err := cs.Write([]byte("REQ")); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(cs, buf); err != nil {
			errc <- err
			return
		}
		if string(buf) != "RESP" {
			errc <- io.ErrUnexpectedEOF
			return
		}
		errc <- nil
	}()

	p := &Proxy{}
	ss, req, err := p.ServerHandshake(ctx, pipeStream{s}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst.String() != "target.example:8443" {
		t.Fatalf("dst = %s, want target.example:8443", req.Dst.String())
	}
	pl := make([]byte, 3)
	if _, err := io.ReadFull(ss, pl); err != nil {
		t.Fatal(err)
	}
	if string(pl) != "REQ" {
		t.Fatalf("payload = %q", pl)
	}
	if _, err := ss.Write([]byte("RESP")); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// TestConnectDefaultPort:CONNECT 只给 host(无端口)→ 默认 443。
func TestConnectDefaultPort(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()
	go func() {
		_, _ = c.Write([]byte("CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		// 读掉 200 应答避免 pipe 阻塞
		br := bufio.NewReader(c)
		_, _ = http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	}()
	p := &Proxy{}
	_, req, err := p.ServerHandshake(ctx, pipeStream{s}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst.String() != "example.com:443" {
		t.Fatalf("dst = %s, want example.com:443", req.Dst.String())
	}
}

// TestPlainForward:明文 absolute-form 请求 → 服务端解出 host:80 + 重建 origin-form 请求(前缀)。
func TestPlainForward(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()
	go func() {
		_, _ = c.Write([]byte("GET http://target.example/path?q=1 HTTP/1.1\r\nHost: target.example\r\nProxy-Connection: keep-alive\r\nUser-Agent: t\r\n\r\n"))
	}()
	p := &Proxy{}
	ss, req, err := p.ServerHandshake(ctx, pipeStream{s}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst.String() != "target.example:80" {
		t.Fatalf("dst = %s, want target.example:80", req.Dst.String())
	}
	// 读回重建的 origin-form 请求:request-target 应为 /path?q=1(不含 scheme/host),含 Host 头,
	// 且 Proxy-Connection 已剥。
	buf := make([]byte, 256)
	n, _ := ss.Read(buf)
	head := string(buf[:n])
	if !strings.HasPrefix(head, "GET /path?q=1 HTTP/1.1\r\n") {
		t.Fatalf("origin-form 行错误:%q", head)
	}
	if !strings.Contains(head, "Host: target.example\r\n") {
		t.Fatalf("缺 Host 头:%q", head)
	}
	if strings.Contains(head, "Proxy-Connection") {
		t.Fatalf("Proxy-Connection 未剥:%q", head)
	}
}

// TestPlainForwardWithBody:带 body 的 POST 明文转发 —— 流式重建应完整含 origin-form 请求行 +
// Content-Length + body,不缓存整个 body(验证 io.Pipe 流式路径正确)。
func TestPlainForwardWithBody(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()
	body := "name=value&x=1"
	go func() {
		req := "POST http://target.example/submit HTTP/1.1\r\nHost: target.example\r\n" +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
		_, _ = c.Write([]byte(req))
	}()
	p := &Proxy{}
	ss, pr, err := p.ServerHandshake(ctx, pipeStream{s}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Dst.String() != "target.example:80" {
		t.Fatalf("dst = %s", pr.Dst.String())
	}
	buf := make([]byte, 512)
	var total string
	// 流式重建可能分多次到达,读到含 body 为止
	for i := 0; i < 8 && !strings.Contains(total, body); i++ {
		n, err := ss.Read(buf)
		total += string(buf[:n])
		if err != nil {
			break
		}
	}
	if !strings.HasPrefix(total, "POST /submit HTTP/1.1\r\n") {
		t.Fatalf("origin-form 请求行错误:%q", total)
	}
	if !strings.Contains(total, "Content-Length: "+strconv.Itoa(len(body))) {
		t.Fatalf("缺 Content-Length:%q", total)
	}
	if !strings.Contains(total, body) {
		t.Fatalf("body 未透传:%q", total)
	}
}

// TestForwardStreamCloseUnblocksWriter:forwardStream.Close 必须关掉 pipe 读端,解阻塞卡在
// pw.Write 的 req.Write goroutine(否则出站拨号失败即拆链时该 goroutine 永久泄漏)。
func TestForwardStreamCloseUnblocksWriter(t *testing.T) {
	pr, pw := io.Pipe()
	below, peer := net.Pipe()
	defer peer.Close()
	fs := &forwardStream{Conn: below, pr: pr, up: pr, below: below}
	writeDone := make(chan error, 1)
	go func() {
		_, err := pw.Write([]byte("请求字节,无人读 pr 时会阻塞")) // 模拟 req.Write 卡在 pw.Write
		writeDone <- err
	}()
	fs.Close() // 关 pr → pw.Write 应立即返回 ErrClosedPipe
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("Close 后 pw.Write 应返回错误")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pw.Write 未被 Close 解阻塞(goroutine 泄漏)")
	}
}
