package hysteria2

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/outbound/direct"
)

// TestHy2RoundTrip:NTR hy2 客户端 → NTR hy2 服务端(QUIC)→ direct → echo。
func TestHy2RoundTrip(t *testing.T) {
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

	tlsConfig, err := ServerTLSConfig("", "")
	if err != nil {
		t.Fatal(err)
	}
	inb, err := NewInbound([]User{{Name: "u", Password: "pw"}}, tlsConfig, "", direct.Outbound{}, nil)
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

	out, err := NewOutbound(Options{Server: pc.LocalAddr().String(), Password: "pw", SNI: "localhost", Insecure: true})
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

	const msg = "hello through hysteria2 quic"
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
