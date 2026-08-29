package tuic

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/outbound/anytls"
	"github.com/LOVECHEN/ntr/outbound/direct"
)

const testUUID = "11111111-1111-1111-1111-111111111111"

// TestTuicRoundTrip:NTR tuic 客户端 → NTR tuic 服务端(QUIC,UUID+password)→ direct → echo。
func TestTuicRoundTrip(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()
	echoDst := addr.FromIPPort(echo.Addr().(*net.TCPAddr).AddrPort())

	tlsConfig, err := anytls.ServerTLSConfig("", "") // 自签 *crypto/tls.Config
	if err != nil {
		t.Fatal(err)
	}
	inb, err := NewInbound([]User{{UUID: testUUID, Password: "pw"}}, tlsConfig, direct.Outbound{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = inb.Serve(ctx, pc) }()

	out, err := NewOutbound(Options{Server: pc.LocalAddr().String(), UUID: testUUID, Password: "pw", SNI: "localhost", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dcancel()
	stream, err := out.DialStream(dctx, echoDst)
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	defer stream.Close()

	const msg = "hello through tuic quic"
	if _, err := stream.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: %q", buf)
	}
}
