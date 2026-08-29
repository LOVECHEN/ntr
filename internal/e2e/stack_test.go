package e2e

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
	_ "github.com/LOVECHEN/ntr/manifest"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/service"
)

// buildLayer 经注册表按名构建一层(name-driven,测试不 import 具体协议/传输实现)。
func buildLayer(t *testing.T, name string, kv map[string]string) any {
	t.Helper()
	d, ok := registry.Lookup(name)
	if !ok {
		t.Fatalf("层 %q 未注册", name)
	}
	m := make(map[string]*spec.Node, len(kv))
	for k, v := range kv {
		m[k] = spec.Scalar(v)
	}
	cfg, err := d.Parse(&spec.Node{Kind: spec.KindMap, Map: m})
	if err != nil {
		t.Fatal(err)
	}
	built, err := d.Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return built
}

// TestStackTLSoverVLESS:真实 [tcp → tls → vless] 全栈跑通字节。
//
// 服务端经 service.BuildInbound 把 {tls, vless} 编译成确定性栈(Band 定序 + 邻接校验),
// 客户端手工叠 tls.ClientWrap → vless.ClientHandshake。证明分层栈组合是架构真能力,
// 且协议/传输都只是插件 —— 服务端侧一行协议特判都没有。
func TestStackTLSoverVLESS(t *testing.T) {
	// echo 靶机。
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()
	dst := addr.FromIPPort(echo.Addr().(*net.TCPAddr).AddrPort())

	// 服务端:编译 [tls, vless] 栈(书写顺序故意乱序,靠 Band 定序)。
	ctx := context.Background()
	handler, _, err := service.BuildInbound(ctx,
		[]service.LayerSpec{
			{Name: "vless", Node: &spec.Node{Kind: spec.KindMap}},
			{Name: "tls", Node: &spec.Node{Kind: spec.KindMap}}, // 空 → 自签临时证书
		},
		ambientAuth{}, // 任意 UUID → Ambient(本测试只验通路)
		service.StaticOutbound{Out: direct.Outbound{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(handler.Below) != 1 {
		t.Fatalf("期望 1 个传输层(tls),得到 %d", len(handler.Below))
	}

	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvLn.Close()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = service.Serve(sctx, srvLn, handler) }()

	// 客户端:裸 TCP → tls.ClientWrap(insecure,自签)→ vless.ClientHandshake。
	tlsClient := buildLayer(t, "tls", map[string]string{"sni": "localhost", "insecure": "true"}).(transport.StreamTransport)
	vlessClient := buildLayer(t, "vless", nil).(proxy.Client)

	raw, err := net.Dial("tcp", srvLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	tlsConn, err := tlsClient.ClientWrap(ctx, pipeStream{raw})
	if err != nil {
		t.Fatalf("tls 握手:%v", err)
	}
	uuid := make([]byte, 16) // 全零 UUID;ambientAuth 一律接受
	cs, err := vlessClient.ClientHandshake(ctx, tlsConn, uuid, dst)
	if err != nil {
		t.Fatalf("vless 握手:%v", err)
	}

	const msg = "bytes through tcp→tls→vless→relay→direct"
	if _, err := cs.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(cs, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: %q", buf)
	}
}
