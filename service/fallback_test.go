package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/outbound/direct"
)

// readNThenFail 是模拟"探测/错凭据"的 proxy.Server:先读 n 字节(模拟消费握手头),再握手失败。
// 用来验证 fallback 会把【已消费的 n 字节 + 后续】完整回放给伪装站。
type readNThenFail struct{ n int }

func (r readNThenFail) ServerHandshake(_ context.Context, below link.Stream, _ proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	buf := make([]byte, r.n)
	_, _ = io.ReadFull(below, buf)
	return nil, nil, errors.New("mock: 握手失败(探测)")
}

// TestFallbackReplaysConsumedBytes:握手失败时,fallback 把【握手已消费字节 + 后续流】原样中继到伪装站,
// 且伪装站的响应回给探测方。核心验证 recordStream 录制/回放的字节完整性。
func TestFallbackReplaysConsumedBytes(t *testing.T) {
	// 伪装站:读满探测应发的全部字节,回一个标记。
	decoy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = decoy.Close() })

	probe := []byte("GET / HTTP/1.1\r\nHost: decoy.example\r\nX: 1234567890\r\n\r\n")
	gotCh := make(chan []byte, 1)
	go func() {
		c, err := decoy.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, len(probe))
		if _, err := io.ReadFull(c, buf); err != nil {
			gotCh <- nil
			return
		}
		gotCh <- buf
		_, _ = c.Write([]byte("DECOY-OK"))
	}()

	// ProxyInbound:握手读 20 字节后失败 + fallback=伪装站。
	handler := &ProxyInbound{
		Proxy:    readNThenFail{n: 20}, // 消费 20 字节再失败,验证这 20 字节也被回放
		Auth:     NewStaticAuth(),
		Out:      StaticOutbound{Out: direct.Outbound{}},
		Fallback: decoy.Addr().String(),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = Serve(ctx, ln, handler) }()

	// 探测方:连入站,发 probe。
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(probe); err != nil {
		t.Fatal(err)
	}

	// 伪装站应收到完整 probe(含被握手消费的前 20 字节)。
	select {
	case got := <-gotCh:
		if !bytes.Equal(got, probe) {
			t.Fatalf("伪装站收到的字节与 probe 不一致:\n got=%q\nwant=%q", got, probe)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("伪装站 5s 内未收到完整 probe(回放丢字节?)")
	}

	// 探测方应收到伪装站的响应(双向中继通)。
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("探测方未收到伪装站响应: %v", err)
	}
	if string(resp) != "DECOY-OK" {
		t.Fatalf("探测方收到 %q,期望 DECOY-OK", resp)
	}
}

// TestFallbackSelectBySNIALPNPath:多站回落规则按 (SNI, ALPN, path) 选伪装站(首条命中;空维=任意)。
func TestFallbackSelectBySNIALPNPath(t *testing.T) {
	h := &ProxyInbound{Fallbacks: []FallbackRule{
		{SNI: []string{"grpc.example"}, Dest: "grpc-by-sni:443"}, // SNI 维:grpc.example → grpc
		{ALPN: []string{"h2"}, Dest: "grpc-backend:443"},         // ALPN 维:h2 → grpc
		{Path: "/ws", Dest: "ws-backend:80"},                     // path 维:/ws → ws
		{ALPN: []string{"http/1.1"}, Path: "/api", Dest: "api"},  // 组合:http1.1 且 /api → api
		{Dest: "default-site:80"},                                // 兜底
	}}
	cases := []struct {
		sni, alpn, path, want string
	}{
		{"grpc.example", "http/1.1", "/x", "grpc-by-sni:443"}, // SNI 命中规则1(先于 ALPN)
		{"other", "h2", "/anything", "grpc-backend:443"},      // 规则1 SNI 不符 → 规则2 ALPN h2 命中
		{"other", "http/1.1", "/ws/chat", "ws-backend:80"},    // → 规则3 path /ws 命中
		{"other", "http/1.1", "/api/v1", "api"},               // → 规则4 ALPN+path 命中
		{"other", "http/1.1", "/", "default-site:80"},         // 都不符 → 兜底
		{"", "", "/", "default-site:80"},                      // 无 SNI/ALPN → 兜底
	}
	for _, c := range cases {
		if got, _ := h.selectFallback(c.sni, c.alpn, c.path); got != c.want {
			t.Errorf("selectFallbackDest(%q,%q,%q)=%q 期望 %q", c.sni, c.alpn, c.path, got, c.want)
		}
	}
	// 无匹配兜底且无默认规则 → 空(关连接)
	h2 := &ProxyInbound{Fallbacks: []FallbackRule{{ALPN: []string{"h2"}, Dest: "x"}}}
	if got, _ := h2.selectFallback("s", "http/1.1", "/"); got != "" {
		t.Errorf("无匹配应返回空,得 %q", got)
	}
	// 单站 Fallback 向后兼容:等价一条无条件规则
	h3 := &ProxyInbound{Fallback: "single:80"}
	if got, _ := h3.selectFallback("s", "anything", "/x"); got != "single:80" {
		t.Errorf("单站 Fallback 应无条件命中,得 %q", got)
	}
}

// TestHTTPRequestPath 校验从请求首行解 path(非 HTTP 返回空)。
func TestHTTPRequestPath(t *testing.T) {
	if p := httpRequestPath([]byte("GET /alpha?x=1 HTTP/1.1\r\nHost: y\r\n\r\n")); p != "/alpha?x=1" {
		t.Errorf("path=%q 期望 /alpha?x=1", p)
	}
	if p := httpRequestPath([]byte("POST /api HTTP/1.0\r\n")); p != "/api" {
		t.Errorf("path=%q 期望 /api", p)
	}
	if p := httpRequestPath([]byte("\x17\x03\x03random-tls-bytes")); p != "" {
		t.Errorf("非 HTTP 应返回空,得 %q", p)
	}
	if p := httpRequestPath([]byte("GET /truncated")); p != "" { // 无 HTTP/ 版本(截断)→ 空
		t.Errorf("截断无版本应返回空,得 %q", p)
	}
}

// TestProxyProtocolHeader 校验 xver 的 PROXY protocol v1(文本)/v2(二进制)编码。
func TestProxyProtocolHeader(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}
	// v1
	if got := string(proxyProtocolHeader(1, src, dst)); got != "PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n" {
		t.Fatalf("v1 头不对: %q", got)
	}
	// v2:12B 签名 + 0x21 + 0x11(INET/STREAM) + 2B len(12) + 4+4+2+2 地址
	v2 := proxyProtocolHeader(2, src, dst)
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	if !bytes.HasPrefix(v2, sig) {
		t.Fatal("v2 签名不对")
	}
	if v2[12] != 0x21 || v2[13] != 0x11 {
		t.Fatalf("v2 verCmd/fam 不对: %02x %02x", v2[12], v2[13])
	}
	if alen := int(v2[14])<<8 | int(v2[15]); alen != 12 || len(v2) != 16+12 {
		t.Fatalf("v2 地址区长不对: alen=%d total=%d", alen, len(v2))
	}
	if !bytes.Equal(v2[16:20], src.IP.To4()) || !bytes.Equal(v2[20:24], dst.IP.To4()) {
		t.Fatal("v2 src/dst IP 不对")
	}
	if sp := int(v2[24])<<8 | int(v2[25]); sp != 51234 {
		t.Fatalf("v2 src port 不对: %d", sp)
	}
	// 非 TCP 地址 → nil
	if proxyProtocolHeader(1, &net.UDPAddr{}, dst) != nil {
		t.Fatal("非 TCP 应返回 nil")
	}
}

// TestNoFallbackClosesOnHandshakeFail:未配 fallback 时,握手失败按原行为关连接(不回放、不泄漏)。
func TestNoFallbackClosesOnHandshakeFail(t *testing.T) {
	handler := &ProxyInbound{
		Proxy: readNThenFail{n: 4},
		Auth:  NewStaticAuth(),
		Out:   StaticOutbound{Out: direct.Outbound{}},
		// Fallback 留空
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = Serve(ctx, ln, handler) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("probe-bytes"))
	// 握手失败无 fallback → 服务端应关闭连接;读到 EOF 即符合预期。
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("未配 fallback 时握手失败应关连接(期望读到 EOF/错误)")
	}
}
