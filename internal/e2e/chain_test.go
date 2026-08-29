package e2e

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/spec"
	_ "github.com/LOVECHEN/ntr/manifest"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/service"
)

// TestChainClientThroughServer:闭合整条链 —— 本地应用 → ntr 出站栈([tls→vless] 客户端)
// → 网络 → ntr 入站栈([tls→vless] 服务端)→ 直连 → echo,再原路返回。
//
// 出站(BuildOutbound)与入站(BuildInbound)是同一套 transport+proxy 插件、方向相反,
// 全程对协议/传输零特判。这是"链式部署 + 协议只是插件"的可执行证据。
func TestChainClientThroughServer(t *testing.T) {
	// echo 靶机(服务端侧 direct 出站的落点)。
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
	echoDst := addr.FromIPPort(echo.Addr().(*net.TCPAddr).AddrPort())

	ctx := context.Background()

	// ntr 服务端:[tls→vless] 入站 → 直连出站。
	inHandler, _, err := service.BuildInbound(ctx,
		[]service.LayerSpec{
			{Name: "tls", Node: &spec.Node{Kind: spec.KindMap}},
			{Name: "vless", Node: &spec.Node{Kind: spec.KindMap}},
		},
		ambientAuth{}, // 任意 UUID → Ambient
		service.StaticOutbound{Out: direct.Outbound{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvLn.Close()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = service.Serve(sctx, srvLn, inHandler) }()

	// ntr 客户端:[tls→vless] 出站,拨上面的服务端。secret=全零 UUID,插件自派生 key。
	out, err := service.BuildOutbound(ctx, srvLn.Addr().String(),
		[]service.LayerSpec{
			{Name: "tls", Node: mapScalar("sni", "localhost", "insecure", "true")},
			{Name: "vless", Node: &spec.Node{Kind: spec.KindMap}},
		},
		"00000000-0000-0000-0000-000000000000",
	)
	if err != nil {
		t.Fatal(err)
	}

	// 本地应用:经出站请求 echoDst(实际路径 = 客户端栈 → 服务端栈 → direct → echo)。
	stream, err := out.DialStream(ctx, echoDst)
	if err != nil {
		t.Fatalf("出站拨号:%v", err)
	}
	defer stream.Close()

	const msg = "round trip through ntr client and ntr server"
	if _, err := stream.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

// mapScalar 从交替的 key,value 造 spec 映射节点。
func mapScalar(kv ...string) *spec.Node {
	m := make(map[string]*spec.Node, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = spec.Scalar(kv[i+1])
	}
	return &spec.Node{Kind: spec.KindMap, Map: m}
}
