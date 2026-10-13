package hysteria1_test

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
	"github.com/LOVECHEN/ntr/outbound/hysteria1"
	"github.com/LOVECHEN/ntr/service"
)

// TestUDPLoopbackMetered:NTR hy1 出站 DialPacket → NTR hy1 入站 → 运行时 SessionPacketDispatch
// (准入 + 计量 + udpNAT)→ direct → 两个 UDP echo。验证:多目标逐包路由、回包来源正确、大于 MTU 的包经库
// 分片重组、UDP 会话按鉴权用户计入其账(身份从库写入的 ctx 回读)。
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
		map[string]cred.ID{"alice@hy1-in": id}, hysteria1.UserFromContext)
	tlsConf, err := anytls.ServerTLSConfig("", "")
	if err != nil {
		t.Fatal(err)
	}
	inb, err := hysteria1.NewInbound([]hysteria1.User{{Name: "alice@hy1-in", Password: "pw"}}, "", 0, 0, tlsConf, direct.Outbound{}, nil, nil, pd)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = inb.Serve(ctx, srv) }()

	out, err := hysteria1.NewOutbound(hysteria1.Options{Server: srv.LocalAddr().String(), Password: "pw", SNI: "localhost", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := out.DialPacket(ctx, e1)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// 往返一包(UDP 可丢,重试几次);big 用于触发库的分片(超 datagram 上限)
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
	roundTrip(e1, []byte("hy1-udp-to-e1"))
	roundTrip(e2, []byte("hy1-udp-to-e2"))
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
