package direct

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
)

// udpEcho 起一个回显 UDP 服务,返回其 addr;收到啥回啥。
func udpEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := uc.ReadFromUDP(b)
			if err != nil {
				return
			}
			_, _ = uc.WriteToUDP(b[:n], from)
		}
	}()
	return uc
}

// TestFullConeSingleSocketMultiTarget:一个 full-cone 出站 socket 对两个不同目标收发,
// 且 ReadPacket 返回真实来源 —— 证 endpoint-independent(full-cone)映射。
func TestFullConeSingleSocketMultiTarget(t *testing.T) {
	a, b := udpEcho(t), udpEcho(t)
	defer a.Close()
	defer b.Close()
	pc, err := (Outbound{FullCone: true}).DialPacket(context.Background(), addr.FromIPPort(a.LocalAddr().(*net.UDPAddr).AddrPort()))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
	localPort := pc.LocalAddr().(*net.UDPAddr).Port

	for _, ep := range []*net.UDPConn{a, b} {
		dst := addr.FromIPPort(ep.LocalAddr().(*net.UDPAddr).AddrPort())
		buf1 := buf.New()
		buf1.Write([]byte("ping"))
		if err := pc.WritePacket(buf1, dst); err != nil {
			t.Fatalf("WritePacket %v: %v", dst, err)
		}
		buf1.Release()
		rb := buf.New()
		src, err := pc.ReadPacket(rb)
		if err != nil {
			t.Fatalf("ReadPacket from %v: %v", dst, err)
		}
		if string(rb.Bytes()) != "ping" {
			t.Errorf("回显=%q 期望 ping", rb.Bytes())
		}
		// ReadPacket 返回真实来源(该 echo 的端口)
		if src.Port != dst.Port {
			t.Errorf("来源端口=%d 期望 %d(真实来源)", src.Port, dst.Port)
		}
		rb.Release()
	}
	// 两个目标共用同一本地端口(单 socket = full-cone)
	if pc.LocalAddr().(*net.UDPAddr).Port != localPort {
		t.Error("full-cone 应始终同一本地端口")
	}
}
