package shadowquic_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/meter"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/outbound/shadowquic"
	"github.com/LOVECHEN/ntr/service"
)

// TestUDPLoopbackMetered:NTR shadowquic 出站 DialPacket → NTR shadowquic 入站 → 运行时 SessionPacketDispatch
// (准入 + 计量 + udpNAT)→ direct → 两个 UDP echo,datagram(0x03)与 stream(0x04)两种关联模式各一遍。
// 验证:每目标 id 宣告 + 多目标逐包路由、回包来源正确、stream 模式可传超 datagram 上限的大包、按 JLS 用户计入其账。
func TestUDPLoopbackMetered(t *testing.T) {
	for _, overStream := range []bool{false, true} {
		name := "datagram"
		if overStream {
			name = "stream"
		}
		t.Run(name, func(t *testing.T) { udpLoopback(t, overStream) })
	}
}

func udpLoopback(t *testing.T, overStream bool) {
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
		map[string]cred.ID{"alice@sq-in": id}, shadowquic.UserFromContext)
	inb, err := shadowquic.NewInbound([]shadowquic.User{{Username: "alice@sq-in", Password: "pw"}}, "example.com", "", nil, direct.Outbound{}, nil, pd)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvAddr := srv.LocalAddr().String()
	_ = srv.Close() // Run 自绑
	go func() { _ = inb.Run(ctx, srvAddr) }()
	time.Sleep(200 * time.Millisecond)

	out, err := shadowquic.NewOutbound(shadowquic.Options{Server: srvAddr, Username: "alice@sq-in", Password: "pw", SNI: "example.com", UDPOverStream: overStream})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := out.DialPacket(ctx, e1)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// 往返一包(UDP 可丢,重试几次)
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
	roundTrip(e1, []byte("sq-udp-to-e1"))
	roundTrip(e2, []byte("sq-udp-to-e2"))
	roundTrip(e1, []byte("sq-udp-to-e1-again")) // 已宣告 id 复用
	if overStream {                             // stream 模式无 datagram 上限
		big := make([]byte, 3000)
		for i := range big {
			big[i] = byte(i)
		}
		roundTrip(e1, big)
	}

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
