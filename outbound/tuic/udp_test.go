package tuic_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/meter"
	"github.com/LOVECHEN/ntr/outbound/anytls"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/outbound/tuic"
	"github.com/LOVECHEN/ntr/service"
)

// TestUDPLoopbackMetered:NTR tuic 出站 DialPacket → NTR tuic 入站 → 运行时 SessionPacketDispatch
// (准入 + 计量 + udpNAT)→ direct → 两个 UDP echo,native(QUIC datagram)与 quic(单向流)两种中继模式各一遍。
// 验证:多目标逐包路由、回包来源正确、大于 MTU 的包经库分片重组、UDP 会话按鉴权用户计入其账。
func TestUDPLoopbackMetered(t *testing.T) {
	for _, mode := range []string{"native", "quic"} {
		t.Run(mode, func(t *testing.T) { udpLoopback(t, mode) })
	}
}

func udpLoopback(t *testing.T, mode string) {
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
		map[string]cred.ID{"alice@tuic-in": id}, tuic.UserFromContext)
	tlsConf, err := anytls.ServerTLSConfig("", "")
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "22222222-2222-2222-2222-222222222222"
	inb, err := tuic.NewInbound([]tuic.User{{Name: "alice@tuic-in", UUID: uuid, Password: "pw"}}, tlsConf, direct.Outbound{}, nil, pd)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = inb.Serve(ctx, srv) }()

	out, err := tuic.NewOutbound(tuic.Options{Server: srv.LocalAddr().String(), UUID: uuid, Password: "pw", SNI: "localhost", Insecure: true, UDPRelayMode: mode})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := out.DialPacket(ctx, e1)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// 往返一包(UDP 可丢,重试几次);big 用于触发库的分片(native 模式超 datagram 上限)
	roundTrip := func(dst addr.Socksaddr, payload []byte) {
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
			got := string(b.Bytes())
			b.Release()
			if got != string(payload) || from.Port != dst.Port {
				t.Fatalf("回包不符:from=%v want %v,len=%d want %d", from, dst, len(got), len(payload))
			}
			return
		}
		t.Fatalf("到 %v 的 UDP 往返多次超时", dst)
	}
	roundTrip(e1, []byte("tuic-udp-to-e1"))
	roundTrip(e2, []byte("tuic-udp-to-e2"))
	big := make([]byte, 3000)
	for i := range big {
		big[i] = byte(i)
	}
	roundTrip(e1, big)

	var found bool
	for _, st := range reg.Snapshot() {
		if cred.ID(st.ID) == id {
			found = true
			if st.ConnsTotal != 1 || st.ConnsLive != 1 {
				t.Fatalf("UDP 会话未按用户计入:conns_total=%d conns_live=%d(期望 1/1)", st.ConnsTotal, st.ConnsLive)
			}
		}
	}
	if !found {
		t.Fatal("计量表里没有 alice")
	}
}
