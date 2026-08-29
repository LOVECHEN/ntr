// Package grpc 实现 gRPC(Gun)传输层(core/transport.StreamTransport)。
//
// gRPC 传输 = 一条 HTTP/2 双向流承载代理数据:客户端 POST /<ServiceName>/Tun,双方以 gRPC 消息
// 帧(5 字节前缀 + protobuf Hunk{bytes data=1})来回传 payload。线格式与 Xray / sing-box 的 gun
// 完全一致。占 Frame band,惯用叠法 [tls(alpn h2), grpc, vless/vmess/trojan],过 CDN/gRPC 网关。
//
// ★瘦核心:自研纯 Go,只用已在依赖树里的 golang.org/x/net/http2 做 HTTP/2 分帧,不引重的 grpc-go。
// gRPC 消息帧 + Hunk protobuf 手写(Hunk 仅一个 bytes 字段,marshal 平凡)。
package grpc

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
)

// maxMsgLen 单条 gRPC 消息上限(防对端发超大 length 触发 OOM)。代理中继写缓冲远小于此,不误伤。
const maxMsgLen = 16 << 20 // 16 MiB

// grpcServerIdleTimeout h2 连接无活跃流的空闲上限:兜住「连上但不开 /Tun 流」的空闲连接
// (正常客户端建连即开 Tun 流,不受影响),防其永久占用 goroutine+fd。
const grpcServerIdleTimeout = 60 * time.Second

// Config 是 gRPC 层自有配置。ServiceName 是 gRPC 服务名(路径 /<ServiceName>/Tun,默认 GunService);
// Authority 是 :authority 伪头(客户端过 CDN 时填伪装域名)。
type Config struct {
	ServiceName string
	Authority   string
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	sn := n.Get("service-name").Str()
	if sn == "" {
		sn = "GunService"
	}
	// authority 是惯用键;也接受 host 别名(与 ws/httpupgrade 一致),防"写成 host 被静默忽略"的坑。
	authority := n.Get("authority").Str()
	if authority == "" {
		authority = n.Get("host").Str()
	}
	return Config{ServiceName: sn, Authority: authority}, nil
}

// Transport 是 gRPC 传输层句柄。
type Transport struct {
	serviceName string
	authority   string
}

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	sn := cfg.ServiceName
	if sn == "" {
		sn = "GunService"
	}
	return &Transport{serviceName: sn, authority: cfg.Authority}, nil
}

// ClientWrap 实现 StreamTransport:在下层 stream 上起 HTTP/2 客户端连接,开 /Tun 双向流,返回承载流。
func (t *Transport) ClientWrap(_ context.Context, below link.Stream) (link.Stream, error) {
	tr := new(http2.Transport)
	cc, err := tr.NewClientConn(below)
	if err != nil {
		return nil, err
	}
	authority := t.authority
	if authority == "" {
		if a := below.RemoteAddr(); a != nil {
			authority = a.String()
		}
	}
	pr, pw := io.Pipe()
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &neturl.URL{Scheme: "https", Host: authority, Path: "/" + t.serviceName + "/Tun"},
		Host:   authority,
		Header: http.Header{"Content-Type": []string{"application/grpc"}, "Te": []string{"trailers"}},
		Body:   pr,
	}
	// ★关键:不能在此阻塞等响应头。grpc-go 服务端(Xray/mihomo)常在收到客户端首个数据帧后才发
	// 响应头,而客户端首帧(上层 vless 握手)要在 ClientWrap 返回后才写 → 若等响应头就死锁。
	// 故 RoundTrip 后台跑,ClientWrap 立即返回可写流(w=pw),响应体在首次 Read 惰性取。
	// respCh 无缓冲 + closed 协调:若在首次 Read 前就 Close,goroutine 自己关掉 resp.Body 防泄漏。
	respCh := make(chan *http.Response)
	errCh := make(chan error, 1)
	closed := make(chan struct{})
	go func() {
		resp, err := cc.RoundTrip(req)
		if err != nil {
			errCh <- err
			return
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			errCh <- errors.New("grpc: 服务端非 200(" + resp.Status + ")")
			return
		}
		select {
		case respCh <- resp: // 交给等待的 Read
		case <-closed: // Close 早于 Read → 自己清理,防 resp.Body 泄漏
			resp.Body.Close()
		}
	}()
	return &grpcConn{w: pw, respCh: respCh, errCh: errCh, closed: closed, below: below}, nil
}

// ServerWrap 实现 StreamTransport:在下层 stream 上跑 HTTP/2 服务端,捕获 /Tun 流。handler 阻塞至
// 代理关闭该流(否则 handler 返回会关掉 h2 stream);ServeConn 在后台 goroutine 跑住整条 h2 连接。
func (t *Transport) ServerWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	// per-conn ctx:ServeConn 因 preface 超时 / 断连 / 错 path handler 返回后连接空闲(IdleTimeout)
	// 结束时 cancel,解阻塞下面等 ready 的 select —— 否则「连上但不开合法 /Tun 流」的空闲/错 path
	// 连接会让本 goroutine+fd 永久钉住(ctx 是服务器级长 ctx,不会因单连接空闲取消)。
	connCtx, cancel := context.WithCancel(ctx)
	ready := make(chan *grpcConn, 1)
	suffix := "/" + t.serviceName + "/Tun"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/Tun") && !strings.HasSuffix(r.URL.Path, suffix) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flush", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		gc := &grpcConn{r: bufio.NewReader(r.Body), rc: r.Body, w: writeFlusher{w, flusher}, done: make(chan struct{}), below: below}
		select {
		case ready <- gc:
		case <-connCtx.Done():
			return
		}
		<-gc.done // 阻塞:保持 handler 与 h2 stream 存活,直到代理关流
	})
	go func() {
		(&http2.Server{IdleTimeout: grpcServerIdleTimeout}).ServeConn(below, &http2.ServeConnOpts{Handler: handler, Context: connCtx})
		cancel() // ServeConn 结束 → 解阻塞 ready 等待(失败路径);成功路径已返回 gc,此处随 relay 收尾触发
	}()
	select {
	case gc := <-ready:
		return gc, nil
	case <-connCtx.Done():
		cancel() // 幂等
		return nil, context.Cause(connCtx)
	}
}

// ---------- gRPC 消息帧 + Hunk protobuf(手写)----------

// writeHunk 把 data 封成一条 gRPC 消息帧:[0x00][len BE32][ 0x0A varint(len) data ]。
func writeHunk(w io.Writer, data []byte) error {
	var lp [10]byte // Hunk 头:0x0A + 最多 9 字节 varint
	lp[0] = 0x0A    // field 1, wire type 2 (LEN)
	n := binary.PutUvarint(lp[1:], uint64(len(data)))
	hunkLen := 1 + n + len(data)
	frame := make([]byte, 5+hunkLen)
	frame[0] = 0 // 未压缩
	binary.BigEndian.PutUint32(frame[1:5], uint32(hunkLen))
	copy(frame[5:], lp[:1+n])
	copy(frame[5+1+n:], data)
	_, err := w.Write(frame)
	return err
}

// readHunk 读一条 gRPC 消息帧,返回内层 Hunk.data。
func readHunk(r *bufio.Reader) ([]byte, error) {
	var prefix [5]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	msgLen := binary.BigEndian.Uint32(prefix[1:5])
	if msgLen > maxMsgLen {
		return nil, errors.New("grpc: 消息超长(疑似恶意 length)")
	}
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	// 解 Hunk:期望 field 1 (0x0A) LEN。
	if len(msg) == 0 {
		return nil, nil // 空消息(如纯 keepalive)
	}
	if msg[0] != 0x0A {
		return nil, errors.New("grpc: 非预期 Hunk 字段")
	}
	dlen, k := binary.Uvarint(msg[1:])
	if k <= 0 || 1+k+int(dlen) > len(msg) {
		return nil, errors.New("grpc: Hunk 长度越界")
	}
	return msg[1+k : 1+k+int(dlen)], nil
}

// grpcConn 把一条 gRPC 双向流抬成 link.Stream。Read 拼 Hunk.data;Write 每次发一个 Hunk 帧。
type grpcConn struct {
	r       *bufio.Reader
	rc      io.Closer // 底层响应/请求体
	w       io.Writer // 客户端=io.PipeWriter;服务端=writeFlusher
	below   link.Stream
	done    chan struct{}       // 仅服务端:关流时 close 以放行 handler
	respCh  chan *http.Response // 仅客户端:后台 RoundTrip 的响应
	errCh   chan error          // 仅客户端:RoundTrip 错误
	closed  chan struct{}       // 仅客户端:Close 时 close,协调 RoundTrip goroutine 清理
	readBuf []byte
	closeMu sync.Once

	// rcMu 保护 rc/bodyClosed:客户端 resolveReader(Read goroutine)与 Close(另一 goroutine)
	// 会并发访问 rc —— 加锁 + bodyClosed 消除数据竞争,并保证「Close 先跑时 resp.Body 不泄漏」。
	rcMu       sync.Mutex
	bodyClosed bool
}

// resolveReader 惰性取响应体(客户端首次 Read 时阻塞等 RoundTrip 完成)。
func (c *grpcConn) resolveReader() error {
	if c.r != nil { // 仅 Read goroutine 访问 c.r,无并发
		return nil
	}
	select {
	case resp := <-c.respCh:
		c.rcMu.Lock()
		if c.bodyClosed { // Close 已先跑 → 无人再关此 body,当场关闭防泄漏
			c.rcMu.Unlock()
			_ = resp.Body.Close()
			return net.ErrClosed
		}
		c.rc = resp.Body
		c.rcMu.Unlock()
		c.r = bufio.NewReader(resp.Body)
		return nil
	case err := <-c.errCh:
		return err
	case <-c.closed:
		return net.ErrClosed
	}
}

func (c *grpcConn) Read(p []byte) (int, error) {
	if err := c.resolveReader(); err != nil {
		return 0, err
	}
	for len(c.readBuf) == 0 {
		data, err := readHunk(c.r)
		if err != nil {
			return 0, err
		}
		c.readBuf = data
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *grpcConn) Write(p []byte) (int, error) {
	if err := writeHunk(c.w, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *grpcConn) Close() error {
	c.closeMu.Do(func() {
		if pw, ok := c.w.(*io.PipeWriter); ok {
			pw.Close()
		}
		if c.closed != nil {
			close(c.closed) // 让 RoundTrip goroutine 清理未被 Read 取走的 resp.Body
		}
		c.rcMu.Lock()
		c.bodyClosed = true // 置位:resolveReader 之后取到 resp 会自行关闭 body(不泄漏)
		rc := c.rc
		c.rcMu.Unlock()
		if rc != nil {
			rc.Close()
		}
		if c.done != nil {
			close(c.done)
		}
	})
	return nil
}

func (c *grpcConn) Unwrap() any                        { return c.below }
func (c *grpcConn) LocalAddr() net.Addr                { return c.below.LocalAddr() }
func (c *grpcConn) RemoteAddr() net.Addr               { return c.below.RemoteAddr() }
func (c *grpcConn) SetDeadline(t time.Time) error      { return c.below.SetDeadline(t) }
func (c *grpcConn) SetReadDeadline(t time.Time) error  { return c.below.SetReadDeadline(t) }
func (c *grpcConn) SetWriteDeadline(t time.Time) error { return c.below.SetWriteDeadline(t) }

// writeFlusher:服务端每写一帧后 flush,保证 h2 及时推给对端。
type writeFlusher struct {
	w io.Writer
	f http.Flusher
}

func (wf writeFlusher) Write(p []byte) (int, error) {
	n, err := wf.w.Write(p)
	if err == nil {
		wf.f.Flush()
	}
	return n, err
}
