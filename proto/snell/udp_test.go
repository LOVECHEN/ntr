package snell

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv6"
)

// TestSnellUDPRoundTrip:NTR snell UDP 客户端(DialPacketConn)↔ 服务端(ServerPacketConn)端到端。
// 表驱动覆盖 v4/v5/v6 —— v4/v5 与 v6 帧/命令逐字节相同(仅 chunk 层不同),此自环同时验证客户端 UDP
// (CmdUDP 握手 + request frame)与服务端 UDP(解析 + 响应)在两代引擎上均自洽。
func TestSnellUDPRoundTrip(t *testing.T) {
	for _, version := range []int{4, 5, 6} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			c, s := net.Pipe()
			defer c.Close()
			defer s.Close()
			ctx := context.Background()
			dst := addr.FromIPPort(netip.MustParseAddrPort("1.2.3.4:53"))
			p := &Proxy{cfg: Config{PSK: testPSK, Version: version}}

			errc := make(chan error, 1)
			go func() { // 客户端
				cpc, err := p.DialPacketConn(ctx, pipeStream{c}, nil, dst)
				if err != nil {
					errc <- err
					return
				}
				wb := buf.New()
				_, _ = wb.Write([]byte("PINGUDP"))
				if err := cpc.WritePacket(wb, dst); err != nil {
					wb.Release()
					errc <- err
					return
				}
				wb.Release()
				rb := buf.New()
				defer rb.Release()
				if _, err := cpc.ReadPacket(rb); err != nil {
					errc <- err
					return
				}
				if string(rb.Bytes()) != "PONGUDP" {
					errc <- fmt.Errorf("client got %q, want PONGUDP", rb.Bytes())
					return
				}
				errc <- nil
			}()

			stream, req, err := p.ServerHandshake(ctx, pipeStream{s}, testAuth{})
			if err != nil {
				t.Fatal(err)
			}
			if req.Network != endpoint.NetworkUDP {
				t.Fatalf("network = %v, want UDP", req.Network)
			}
			spc, err := p.ServerPacketConn(stream, addr.Socksaddr{})
			if err != nil {
				t.Fatal(err)
			}
			rb := buf.New()
			defer rb.Release()
			rdst, err := spc.ReadPacket(rb)
			if err != nil {
				t.Fatal(err)
			}
			if rdst.String() != "1.2.3.4:53" {
				t.Fatalf("server target = %s, want 1.2.3.4:53", rdst.String())
			}
			if string(rb.Bytes()) != "PINGUDP" {
				t.Fatalf("server data = %q, want PINGUDP", rb.Bytes())
			}
			wb := buf.New()
			_, _ = wb.Write([]byte("PONGUDP"))
			if err := spc.WritePacket(wb, rdst); err != nil {
				wb.Release()
				t.Fatal(err)
			}
			wb.Release()
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestServerUDPPiggyback:客户端把 CmdUDP 命令与第一个 UDP frame 合并进同一 chunk(piggyback),
// 服务端须 ①识别 Network=UDP ②经 ServerPacketConn 适配多目标 PacketConn ③首个 ReadPacket 从
// piggyback 的 initial 解出正确 target+data(不丢第一个数据报,vendored serveUDP 会丢)。
func TestServerUDPPiggyback(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errc := make(chan error, 1)
	go func() { // 客户端:vendored Sender + 手构 CmdUDP 命令 + piggyback 第一个 UDP frame
		snd := snellv6.NewSender(testPSK, false)
		cmd := []byte{1, snellv6.CmdUDP, 0}                                // ver=1, CmdUDP, idLen=0
		frame := append([]byte{1, 0, 4, 1, 2, 3, 4, 0, 53}, "DNSQUERY"...) // [01][00][type4][ip][port53][data]
		enc, e := snd.EncodeChunk(append(cmd, frame...))
		if e != nil {
			errc <- e
			return
		}
		_, e = c.Write(enc)
		errc <- e
	}()

	p := &Proxy{cfg: Config{PSK: testPSK, Version: 6}}
	stream, req, err := p.ServerHandshake(context.Background(), pipeStream{s}, testAuth{})
	if err != nil {
		t.Fatal(err)
	}
	if req.Network != endpoint.NetworkUDP {
		t.Fatalf("network = %v, want UDP", req.Network)
	}
	spc, err := p.ServerPacketConn(stream, addr.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	b := buf.New()
	defer b.Release()
	dst, err := spc.ReadPacket(b)
	if err != nil {
		t.Fatal(err)
	}
	if dst.String() != "1.2.3.4:53" {
		t.Fatalf("target = %s, want 1.2.3.4:53", dst.String())
	}
	if string(b.Bytes()) != "DNSQUERY" {
		t.Fatalf("data = %q, want DNSQUERY(piggyback 第一个数据报丢失?)", b.Bytes())
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// TestParseTarget:snell UDP frame 的 "host:port" → Socksaddr(IP 字面量 vs 域名)。
func TestParseTarget(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		fqdn bool
	}{
		{"1.2.3.4:53", "1.2.3.4:53", false},
		{"[2001:db8::1]:443", "[2001:db8::1]:443", false},
		{"example.com:80", "example.com:80", true},
	} {
		sa, err := parseTarget(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if sa.String() != tc.want {
			t.Fatalf("%s → %s, want %s", tc.in, sa.String(), tc.want)
		}
		if sa.IsFqdn() != tc.fqdn {
			t.Fatalf("%s: IsFqdn=%v, want %v", tc.in, sa.IsFqdn(), tc.fqdn)
		}
	}
}
