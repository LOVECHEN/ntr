package trusttunnel

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/meter"
	"github.com/LOVECHEN/ntr/outbound/anytls"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/service"
)

// TestIP16 黄金向量:IPv4 = 12 字节 0 + 4 字节地址(非 ::ffff 映射);::1 不被误读成 IPv4 0.0.0.1。
func TestIP16(t *testing.T) {
	v4 := encodeIP16(netip.MustParseAddr("192.0.2.7"))
	if want := [16]byte{12: 192, 13: 0, 14: 2, 15: 7}; v4 != want {
		t.Fatalf("IPv4 编码 % x,期望 % x", v4, want)
	}
	if got := encodeIP16(netip.MustParseAddr("::ffff:192.0.2.7")); got != v4 {
		t.Fatalf("IPv4 映射地址应按 IPv4 编码,得 % x", got)
	}
	for _, s := range []string{"192.0.2.7", "::1", "2001:db8::5", "0.0.0.0"} {
		a := netip.MustParseAddr(s)
		if got := decodeIP16(encodeIP16(a)); got != a {
			t.Fatalf("%s 往返得 %s", s, got)
		}
	}
}

// TestUDPLoopbackMetered:NTR trusttunnel 出站 DialPacket(_udp2)→ NTR 入站 → 运行时 SessionPacketDispatch
// (准入 + 计量 + udpNAT)→ direct → 两个 UDP echo。验证双向帧格式自洽、多目标逐包路由、回包来源、
// IP 字面量 FQDN 目标先解析(帧里只许 IP)、会话按 Basic 用户计入其账。
func TestUDPLoopbackMetered(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	echo := func() addr.Socksaddr {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		go func() {
			b := make([]byte, 65535)
			for {
				n, from, err := pc.ReadFrom(b)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(b[:n], from)
			}
		}()
		return addr.FromIPPort(pc.LocalAddr().(*net.UDPAddr).AddrPort())
	}
	e1, e2 := echo(), echo()

	reg := meter.NewRegistry()
	id := reg.IDForBill("alice")
	pd := service.SessionPacketDispatch(direct.Outbound{}, &service.Admitter{Meter: reg},
		map[string]cred.ID{"alice@tt-in": id}, UserFromContext)
	tlsConf, err := anytls.ServerTLSConfig("", "")
	if err != nil {
		t.Fatal(err)
	}
	inb, err := NewInbound([]User{{Name: "alice@tt-in", Password: "pw"}}, tlsConf, direct.Outbound{}, nil, pd)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = inb.HandleStream(ctx, connStreamTest{c}, &endpoint.Metadata{}) }(c)
		}
	}()

	out, err := NewOutbound(Options{Server: ln.Addr().String(), User: "alice@tt-in", Password: "pw", SNI: "localhost", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := out.DialPacket(ctx, e1)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	roundTrip := func(dst, wantFrom addr.Socksaddr, payload []byte) {
		t.Helper()
		for attempt := 0; attempt < 5; attempt++ {
			if err := pc.WritePacket(buf.As(append([]byte(nil), payload...)), dst); err != nil {
				t.Fatalf("WritePacket %v: %v", dst, err)
			}
			_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
			b := buf.New()
			from, err := pc.ReadPacket(b)
			if err != nil {
				b.Release()
				continue
			}
			got := append([]byte(nil), b.Bytes()...)
			b.Release()
			if !bytes.Equal(got, payload) || from.Addr != wantFrom.Addr || from.Port != wantFrom.Port {
				t.Fatalf("回包不符:from=%v want %v,len=%d want %d", from, wantFrom, len(got), len(payload))
			}
			return
		}
		t.Fatalf("到 %v 的 UDP 往返多次超时", dst)
	}
	roundTrip(e1, e1, []byte("tt-udp-to-e1"))
	roundTrip(e2, e2, []byte("tt-udp-to-e2"))
	literal := addr.FromFqdn(e1.Addr.String(), e1.Port) // socks5 客户端常以 ATYP=3 发 "127.0.0.1"
	roundTrip(literal, e1, []byte("tt-udp-literal-fqdn"))
	big := bytes.Repeat([]byte{0x5a}, 3000) // 流式帧,无 datagram 上限
	roundTrip(e2, e2, big)

	for _, st := range reg.Snapshot() {
		if cred.ID(st.ID) == id {
			if st.ConnsTotal != 1 || st.ConnsLive != 1 {
				t.Fatalf("UDP 会话未按用户计入:conns_total=%d conns_live=%d(期望 1/1)", st.ConnsTotal, st.ConnsLive)
			}
			return
		}
	}
	t.Fatal("计量表里没有 alice")
}
