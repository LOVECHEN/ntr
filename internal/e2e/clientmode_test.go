package e2e

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/spec"
	_ "github.com/LOVECHEN/ntr/manifest"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/service"
)

// TestClientModeSocksThroughChain:真实 SOCKS5 客户端 → ntr-client(socks 入站 → [tls→vless]
// 出站)→ ntr-server([tls→vless] 入站 → direct)→ echo。这是"客户端模式"的完整实测:
// 本机应用只会说 SOCKS5,ntr-client 把它接上加密上游。
func TestClientModeSocksThroughChain(t *testing.T) {
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
	echoDst := addr.FromIPPort(echo.Addr().(*net.TCPAddr).AddrPort())

	ctx := context.Background()

	// ntr-server:[tls→vless] 入站 → 直连。
	srvHandler, _, err := service.BuildInbound(ctx,
		[]service.LayerSpec{
			{Name: "tls", Node: &spec.Node{Kind: spec.KindMap}},
			{Name: "vless", Node: &spec.Node{Kind: spec.KindMap}},
		},
		ambientAuth{},
		service.StaticOutbound{Out: direct.Outbound{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	srvLn := listen(t)
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = service.Serve(sctx, srvLn, srvHandler) }()

	// ntr-client:本地 socks 入站 → [tls→vless] 出站转上游 srvLn。
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
	cliHandler, _, err := service.BuildInbound(ctx,
		[]service.LayerSpec{{Name: "socks", Node: &spec.Node{Kind: spec.KindMap}}},
		service.NewStaticAuth(),
		service.StaticOutbound{Out: out},
	)
	if err != nil {
		t.Fatal(err)
	}
	cliLn := listen(t)
	go func() { _ = service.Serve(sctx, cliLn, cliHandler) }()

	// 本机应用:标准 SOCKS5 连本地 ntr-client,请求 echoDst。
	stream := socks5Dial(t, cliLn.Addr().String(), echoDst)
	defer stream.Close()

	const msg = "socks client → ntr-client → ntr-server → echo"
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

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// socks5Dial 跑标准 SOCKS5 no-auth CONNECT 握手,返回可直接读写 payload 的连接。
func socks5Dial(t *testing.T, socksAddr string, dst addr.Socksaddr) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(c, sel); err != nil {
		t.Fatal(err)
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		t.Fatalf("SOCKS 方法协商失败:%x", sel)
	}
	req := []byte{0x05, 0x01, 0x00}
	if dst.IsFqdn() {
		req = append(req, 0x03, byte(len(dst.Fqdn)))
		req = append(req, dst.Fqdn...)
	} else if dst.Addr.Is4() {
		a := dst.Addr.As4()
		req = append(req, 0x01)
		req = append(req, a[:]...)
	} else {
		a := dst.Addr.As16()
		req = append(req, 0x04)
		req = append(req, a[:]...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], dst.Port)
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10) // VER REP RSV ATYP(v4) BND.ADDR(4) BND.PORT(2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("SOCKS CONNECT 被拒:REP=%d", reply[1])
	}
	return c
}
