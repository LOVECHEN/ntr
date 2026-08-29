package reverse

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/outbound/upstream"
	"github.com/LOVECHEN/ntr/service"
)

// udpEchoServer 起一个本地 UDP echo(Bridge 落地目标)。
func udpEchoServer(t *testing.T) (*net.UDPConn, addr.Socksaddr) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		p := make([]byte, 64*1024)
		for {
			n, src, err := c.ReadFromUDP(p)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDP(p[:n], src)
		}
	}()
	return c, addr.FromIPPort(c.LocalAddr().(*net.UDPAddr).AddrPort())
}

// TestReverseUDPEndToEnd:真 VLESS 隧道上的反连【UDP】闭环——
//
//	user ──(vless UDP 拨 echo 地址)──▶ Portal 挑隧道开 mux UDP 子流 ─反向复用─▶ Bridge 直连
//	落地本地 UDP echo ──回程──▶ user 收到回显。
//
// 验证 Portal UDP 用户流桥(relayUDP + socksNetAddr)+ muxcool UDP 子流(landUDP/deliverUDP)
// 端到端跑通,协议无关(隧道用 vless)。
func TestReverseUDPEndToEnd(t *testing.T) {
	echo, echoDst := udpEchoServer(t)
	defer echo.Close()

	plugin := buildVLESS(t)
	uuidKey, _ := hex.DecodeString("00112233445566778899aabbccddeeff")

	auth := service.NewStaticAuth()
	auth.Add("vless", uuidKey, cred.Ref{ID: cred.UserBase + 1})
	portal := &Portal{
		HS:       &service.ProxyInbound{Proxy: plugin.(proxy.Server), Auth: auth},
		Control:  DefaultControlDomain,
		Interval: 200 * time.Millisecond,
	}
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = service.Serve(ctx, pln, portal) }()

	bridge := &Bridge{
		Dial:    &upstream.Outbound{Server: pln.Addr().String(), Client: plugin.(proxy.Client), Key: uuidKey},
		Control: addr.FromFqdn(DefaultControlDomain, 0),
		Pool:    1,
	}
	go func() { _ = bridge.Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for portal.TunnelCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("隧道未就绪")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// user:经 vless UDP 拨 echo 地址,流量应反向复用回 Bridge 落地。
	userOut := &upstream.Outbound{Server: pln.Addr().String(), Client: plugin.(proxy.Client), Key: uuidKey}
	upc, err := userOut.DialPacket(ctx, echoDst)
	if err != nil {
		t.Fatalf("user UDP 拨号失败:%v", err)
	}
	defer upc.Close()

	const msg = "pingudp-through-reverse"
	wb := buf.New()
	_, _ = wb.Write([]byte(msg))
	if err := upc.WritePacket(wb, echoDst); err != nil {
		wb.Release()
		t.Fatal(err)
	}
	wb.Release()

	_ = upc.SetDeadline(time.Now().Add(3 * time.Second))
	rb := buf.New()
	defer rb.Release()
	if _, err := upc.ReadPacket(rb); err != nil {
		t.Fatalf("反连 UDP 回程读取失败:%v", err)
	}
	if string(rb.Bytes()) != msg {
		t.Fatalf("UDP echo 不匹配:%q", rb.Bytes())
	}
}
