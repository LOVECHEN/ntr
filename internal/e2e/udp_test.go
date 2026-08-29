package e2e

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/spec"
	_ "github.com/LOVECHEN/ntr/manifest"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/service"
)

// TestVLESSUDPPipeline:VLESS UDP-over-stream 全链 —— 客户端 DialPacketConn(Command=UDP)
// → ntr-server(Network=UDP 判定 → 能力发现 ServerPacketConn → direct UDP 出站)→ UDP echo。
func TestVLESSUDPPipeline(t *testing.T) {
	// UDP echo 靶机。
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uconn.Close()
	go func() {
		p := make([]byte, 2048)
		for {
			n, raddr, err := uconn.ReadFromUDP(p)
			if err != nil {
				return
			}
			_, _ = uconn.WriteToUDP(p[:n], raddr)
		}
	}()
	udpDst := addr.FromIPPort(uconn.LocalAddr().(*net.UDPAddr).AddrPort())

	ctx := context.Background()

	// ntr-server:vless 入站(裸,隔离验证 UDP 分帧)→ 直连出站。
	handler, _, err := service.BuildInbound(ctx,
		[]service.LayerSpec{{Name: "vless", Node: &spec.Node{Kind: spec.KindMap}}},
		ambientAuth{},
		service.StaticOutbound{Out: direct.Outbound{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	srvLn := listen(t)
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = service.Serve(sctx, srvLn, handler) }()

	// 客户端:VLESS UDP 关联。
	plugin := buildLayer(t, "vless", nil)
	pcc, ok := plugin.(proxy.PacketConnClient)
	if !ok {
		t.Fatal("vless 未实现 PacketConnClient")
	}
	raw, err := net.Dial("tcp", srvLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	uuid := make([]byte, 16)
	pc, err := pcc.DialPacketConn(ctx, pipeStream{raw}, uuid, udpDst)
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))

	const msg = "ping over vless udp"
	wb := buf.New()
	_, _ = wb.Write([]byte(msg))
	if err := pc.WritePacket(wb, udpDst); err != nil {
		t.Fatal(err)
	}
	wb.Release()

	rb := buf.New()
	defer rb.Release()
	from, err := pc.ReadPacket(rb)
	if err != nil {
		t.Fatal(err)
	}
	if string(rb.Bytes()) != msg {
		t.Fatalf("udp echo mismatch: %q", rb.Bytes())
	}
	if from.String() != udpDst.String() {
		t.Fatalf("packet from %s, want %s", from.String(), udpDst.String())
	}
}

// TestChainUDPThroughUpstream:UDP 经完整两节点链 —— upstream 出站([tls→vless] 承载 UDP)
// → ntr-server([tls→vless] UDP 入站 → direct UDP)→ UDP echo。证明 UDP 也走同一套栈。
func TestChainUDPThroughUpstream(t *testing.T) {
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uconn.Close()
	go func() {
		p := make([]byte, 2048)
		for {
			n, raddr, err := uconn.ReadFromUDP(p)
			if err != nil {
				return
			}
			_, _ = uconn.WriteToUDP(p[:n], raddr)
		}
	}()
	udpDst := addr.FromIPPort(uconn.LocalAddr().(*net.UDPAddr).AddrPort())

	ctx := context.Background()

	// ntr-server:[tls→vless] 入站 → 直连。
	handler, _, err := service.BuildInbound(ctx,
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
	go func() { _ = service.Serve(sctx, srvLn, handler) }()

	// upstream 出站:[tls→vless]。
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

	// 调用方(未来 udpnat / SOCKS-UDP 入站会这样调):经上游发 UDP。
	pc, err := out.DialPacket(ctx, udpDst)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))

	const msg = "udp through the whole chain"
	wb := buf.New()
	_, _ = wb.Write([]byte(msg))
	if err := pc.WritePacket(wb, udpDst); err != nil {
		t.Fatal(err)
	}
	wb.Release()

	rb := buf.New()
	defer rb.Release()
	if _, err := pc.ReadPacket(rb); err != nil {
		t.Fatal(err)
	}
	if string(rb.Bytes()) != msg {
		t.Fatalf("udp chain echo mismatch: %q", rb.Bytes())
	}
}
