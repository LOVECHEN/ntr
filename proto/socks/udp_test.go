package socks

import (
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
)

// TestSocksUDPHeaderRoundTrip:encodeUDPHeader → parseUDPAddr 往返(域名/IPv4/IPv6)+ 截断不 panic。
func TestSocksUDPHeaderRoundTrip(t *testing.T) {
	cases := []addr.Socksaddr{
		addr.FromFqdn("target.example", 53),
		addr.FromFqdn("a.b.c.example.com", 443),
	}
	for _, want := range cases {
		hdr := encodeUDPHeader(want) // [RSV(2)][FRAG][ATYP][ADDR][PORT]
		if len(hdr) < 4 || hdr[0] != 0 || hdr[1] != 0 || hdr[2] != 0 {
			t.Fatalf("头前缀错:%x", hdr[:4])
		}
		got, n, err := parseUDPAddr(hdr[3:]) // 跳过 RSV+FRAG
		if err != nil {
			t.Fatalf("%s: parse err %v", want.String(), err)
		}
		if got.String() != want.String() {
			t.Fatalf("往返 %s → %s", want.String(), got.String())
		}
		if 3+n != len(hdr) {
			t.Fatalf("消耗字节数错:3+%d != %d", n, len(hdr))
		}
	}
	// 截断输入不 panic
	if _, _, err := parseUDPAddr([]byte{atypIPv4, 1, 2}); err == nil {
		t.Fatal("截断的 IPv4 地址应报错")
	}
	if _, _, err := parseUDPAddr(nil); err == nil {
		t.Fatal("空输入应报错")
	}
}

// TestSocksUDPSourceLockAndDrop:中继 socket 非连接式 —— 首包锁定客户端;非该客户端的包丢弃(防劫持);
// 坏包/分片丢弃且不拖垮关联(只有 socket 关闭才致命)。
func TestSocksUDPSourceLockAndDrop(t *testing.T) {
	lo := net.IPv4(127, 0, 0, 1)
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: lo})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	c := &socksUDPConn{udp: relay}
	ra := relay.LocalAddr().(*net.UDPAddr)
	clientA, _ := net.ListenUDP("udp", &net.UDPAddr{IP: lo})
	defer clientA.Close()
	clientB, _ := net.ListenUDP("udp", &net.UDPAddr{IP: lo})
	defer clientB.Close()

	dst := addr.FromFqdn("t1", 53)
	mk := func(payload string) []byte { return append(encodeUDPHeader(dst), payload...) }
	_ = relay.SetReadDeadline(time.Now().Add(3 * time.Second))

	// A 首包 → 返回 + 锁定 client=A
	_, _ = clientA.WriteToUDP(mk("A1"), ra)
	b := buf.New()
	defer b.Release()
	d, err := c.ReadPacket(b)
	if err != nil || d.String() != "t1:53" || string(b.Bytes()) != "A1" {
		t.Fatalf("首包:%v %q", err, b.Bytes())
	}

	// B(异源)劫持包 + A 第二包 → 必须丢 B、返回 A(顺序无关:ReadPacket 绝不返回 B 的)
	_, _ = clientB.WriteToUDP(mk("B-HIJACK"), ra)
	time.Sleep(50 * time.Millisecond)
	_, _ = clientA.WriteToUDP(mk("A2"), ra)
	b.Reset()
	if _, err := c.ReadPacket(b); err != nil || string(b.Bytes()) != "A2" {
		t.Fatalf("应丢 B 返回 A:%v %q", err, b.Bytes())
	}

	// A 坏包(过短)+ A 好包 → 丢坏包、返回好包
	_, _ = clientA.WriteToUDP([]byte{0, 0, 0}, ra)
	time.Sleep(50 * time.Millisecond)
	_, _ = clientA.WriteToUDP(mk("A3"), ra)
	b.Reset()
	if _, err := c.ReadPacket(b); err != nil || string(b.Bytes()) != "A3" {
		t.Fatalf("应丢坏包返回好包:%v %q", err, b.Bytes())
	}
}
