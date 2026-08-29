package shadowsocks

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

// TestSSUDPSelfLoop 自环 e2e:NTR SS UDP 客户端(DialNativePacketConn)↔ NTR SS UDP 服务端
// (ServePacket)经真 UDP socket 往返,走真正的 SS AEAD 封装/解封装。sink 直接 echo,不依赖
// service/udpNAT/Docker。验两代加密两条 headroom 路径 + buffer 桥(不 panic、不双释放、边界不破)。
func TestSSUDPSelfLoop(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(method, func(t *testing.T) {
			password := "loveudptest12345" // 经典任意口令
			if method[:5] == "2022-" {
				password = "bG92ZXVkcHRlc3QxMjM0NQ==" // base64(16B "loveudptest12345"):2022-aes-128 需 16 字节密钥
			}
			built, err := Build(context.Background(), Config{Method: method, Password: password}, nil)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			p := built.(*Proxy)

			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// 服务端:sink 拿到已解密的多目标 clientPC,原样 echo(payload+dst 回写)。
			go func() {
				_ = p.ServePacket(ctx, pc, func(clientPC link.PacketConn) {
					b := buf.New()
					defer b.Release()
					for {
						b.Reset()
						dst, err := clientPC.ReadPacket(b)
						if err != nil {
							return
						}
						if err := clientPC.WritePacket(b, dst); err != nil {
							return
						}
					}
				})
			}()

			// 客户端:原生 UDP 出站到服务端,发一个包到 8.8.8.8:53(仅作 SS 目标头,不真解析),收 echo。
			target := addr.FromIPPort(netip.MustParseAddrPort("8.8.8.8:53"))
			cc, err := p.DialNativePacketConn(ctx, pc.LocalAddr().String(), nil, target)
			if err != nil {
				t.Fatalf("DialNativePacketConn: %v", err)
			}
			defer cc.Close()

			msg := []byte("PINGUDP-selfloop-42")
			wb := buf.New()
			copy(wb.ExtendTail(len(msg)), msg)
			if err := cc.WritePacket(wb, target); err != nil {
				wb.Release()
				t.Fatalf("client WritePacket: %v", err)
			}
			wb.Release()

			_ = cc.SetDeadline(time.Now().Add(3 * time.Second))
			rb := buf.New()
			defer rb.Release()
			gotDst, err := cc.ReadPacket(rb)
			if err != nil {
				t.Fatalf("client ReadPacket: %v", err)
			}
			if string(rb.Bytes()) != string(msg) {
				t.Fatalf("echo 不符:got %q want %q", rb.Bytes(), msg)
			}
			// 单目标客户端:回包源恒为握手目标。
			if gotDst.Port != target.Port {
				t.Fatalf("回程 dst 端口不符:got %d want %d", gotDst.Port, target.Port)
			}
		})
	}
}
