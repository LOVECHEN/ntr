package e2e

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
	_ "github.com/LOVECHEN/ntr/manifest"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/proto/trojan"
	"github.com/LOVECHEN/ntr/service"
)

// TestStackTLSoverTrojan:新协议 Trojan 零改动核心/service/cmd,直接叠进既有 [tls→proxy]
// 栈机制跑通。证明"协议只是插件":加协议 = 新包 + manifest 一行,别处一字不动。
func TestStackTLSoverTrojan(t *testing.T) {
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

	// 服务端:[tls, trojan] 栈 + 按 password hash 登记的用户。
	const password = "s3cr3t-trojan-pass"
	auth := service.NewStaticAuth()
	auth.Add("trojan", trojan.Key(password), cred.Ref{ID: cred.UserBase + 9})

	ctx := context.Background()
	handler, _, err := service.BuildInbound(ctx,
		[]service.LayerSpec{
			{Name: "trojan", Node: &spec.Node{Kind: spec.KindMap}},
			{Name: "tls", Node: &spec.Node{Kind: spec.KindMap}},
		},
		auth,
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
	go func() { _ = service.Serve(sctx, srvLn, handler) }()

	// 客户端:裸 TCP → tls.ClientWrap → trojan.ClientHandshake(password)。
	tlsClient := buildLayer(t, "tls", map[string]string{"sni": "localhost", "insecure": "true"}).(transport.StreamTransport)
	trojanClient := buildLayer(t, "trojan", nil).(proxy.Client)

	raw, err := net.Dial("tcp", srvLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	tlsConn, err := tlsClient.ClientWrap(ctx, pipeStream{raw})
	if err != nil {
		t.Fatalf("tls 握手:%v", err)
	}
	cs, err := trojanClient.ClientHandshake(ctx, tlsConn, []byte(password), dst)
	if err != nil {
		t.Fatalf("trojan 握手:%v", err)
	}

	const msg = "bytes through tcp→tls→trojan→relay→direct"
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
