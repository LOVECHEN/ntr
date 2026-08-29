package reverse

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	_ "github.com/LOVECHEN/ntr/manifest"
	"github.com/LOVECHEN/ntr/outbound/upstream"
	"github.com/LOVECHEN/ntr/service"
)

// buildVLESS 经注册表按名取 VLESS 插件(name-driven,测试不 import proto/vless)。
func buildVLESS(t *testing.T) any {
	t.Helper()
	d, ok := registry.Lookup("vless")
	if !ok {
		t.Fatal("vless 未注册(manifest 没链接进来?)")
	}
	cfg, err := d.Parse(&spec.Node{Kind: spec.KindMap, Map: map[string]*spec.Node{}})
	if err != nil {
		t.Fatal(err)
	}
	built, err := d.Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func echoServer(t *testing.T) (net.Listener, addr.Socksaddr) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()
	return ln, addr.FromIPPort(ln.Addr().(*net.TCPAddr).AddrPort())
}

// TestReverseEndToEnd:真 VLESS 隧道上的完整反连闭环——
//
//	Bridge ──(vless 拨 reverse.ntr:0)──▶ Portal 注册隧道
//	user  ──(vless 拨 echo 地址)──▶ Portal 挑隧道开子流 ─反向复用─▶ Bridge 直连落地 echo
//
// 验证 reverse 编排(Portal/Bridge/pool/muxcool)在【真实代理握手】之上端到端跑通,
// 且协议无关(隧道用 vless,reverse 代码零 import 协议)。
func TestReverseEndToEnd(t *testing.T) {
	echo, echoDst := echoServer(t)
	defer echo.Close()

	plugin := buildVLESS(t)
	uuidKey, _ := hex.DecodeString("00112233445566778899aabbccddeeff")

	// —— Portal:真 TCP 监听 + service.Serve(Portal) ——
	auth := service.NewStaticAuth()
	auth.Add("vless", uuidKey, cred.Ref{ID: cred.UserBase + 1})
	portal := &Portal{
		HS:       &service.ProxyInbound{Proxy: plugin.(proxy.Server), Auth: auth},
		Control:  DefaultControlDomain,
		Interval: 200 * time.Millisecond, // 测试:快心跳
	}
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = service.Serve(ctx, pln, portal) }()

	// —— Bridge:经 vless 出站拨 Portal 建隧道,落地用 net.Dialer 直连 ——
	bridge := &Bridge{
		Dial:    &upstream.Outbound{Server: pln.Addr().String(), Client: plugin.(proxy.Client), Key: uuidKey},
		Control: addr.FromFqdn(DefaultControlDomain, 0),
		Pool:    1,
	}
	go func() { _ = bridge.Run(ctx) }()

	// 等隧道就绪(Bridge 拨通 + Portal 注册)。
	deadline := time.Now().Add(3 * time.Second)
	for portal.TunnelCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("隧道未就绪:Bridge 未连上 Portal")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// —— user:经 vless 出站拨 echo 地址,流量应反向复用回 Bridge 落地 ——
	userOut := &upstream.Outbound{Server: pln.Addr().String(), Client: plugin.(proxy.Client), Key: uuidKey}
	us, err := userOut.DialStream(ctx, echoDst)
	if err != nil {
		t.Fatalf("user 拨号失败:%v", err)
	}
	defer us.Close()

	const msg = "hello through the reverse tunnel"
	if _, err := us.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = us.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(us, buf); err != nil {
		t.Fatalf("反连回程读取失败:%v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo 不匹配:%q", buf)
	}
}
