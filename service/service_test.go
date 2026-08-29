package service

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	_ "github.com/LOVECHEN/ntr/manifest"
	"github.com/LOVECHEN/ntr/outbound/direct"
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

// startServer 起完整 ntr 服务端(真实 TCP 监听 + Serve + ProxyInbound + 直连出站)。
func startServer(t *testing.T, plugin any, auth proxy.Authenticator) net.Addr {
	t.Helper()
	handler := &ProxyInbound{
		Proxy: plugin.(proxy.Server),
		Auth:  auth,
		Out:   StaticOutbound{Out: direct.Outbound{}},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = Serve(ctx, ln, handler) }()
	return ln.Addr()
}

// TestVLESSServerEndToEnd:VLESS 客户端 → 完整 ntr 服务端(监听→握手→中继→直连)→ echo,全通。
func TestVLESSServerEndToEnd(t *testing.T) {
	echo, dst := echoServer(t)
	defer echo.Close()

	plugin := buildVLESS(t)
	uuidKey, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	auth := NewStaticAuth()
	auth.Add("vless", uuidKey, cred.Ref{ID: cred.UserBase + 1})
	srvAddr := startServer(t, plugin, auth)

	raw, err := net.Dial("tcp", srvAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	cs, err := plugin.(proxy.Client).ClientHandshake(context.Background(), connStream{raw}, uuidKey, dst)
	if err != nil {
		t.Fatal(err)
	}
	const msg = "hello through the whole ntr server"
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

// TestVLESSUnknownUserRejected:错 UUID 不在凭据表 → 服务端握手响亮拒绝、断连,客户端读不到回程。
func TestVLESSUnknownUserRejected(t *testing.T) {
	echo, dst := echoServer(t)
	defer echo.Close()

	plugin := buildVLESS(t)
	knownKey, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	auth := NewStaticAuth()
	auth.Add("vless", knownKey, cred.Ref{ID: cred.UserBase + 1})
	srvAddr := startServer(t, plugin, auth)

	raw, err := net.Dial("tcp", srvAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	wrongKey, _ := hex.DecodeString("ffffffffffffffffffffffffffffffff")
	cs, err := plugin.(proxy.Client).ClientHandshake(context.Background(), connStream{raw}, wrongKey, dst)
	if err != nil {
		t.Fatal(err) // 客户端只写头,不该在此失败
	}
	_, _ = cs.Write([]byte("should never be echoed"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(cs, buf); err == nil {
		t.Fatal("未知用户竟拿到回程数据;应被服务端拒绝断连")
	}
}
