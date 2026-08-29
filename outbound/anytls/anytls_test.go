package anytls

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/outbound/direct"
)

// TestAnytlsRoundTrip:NTR anytls 客户端 → NTR anytls 服务端(会话解复用)→ direct → echo。
func TestAnytlsRoundTrip(t *testing.T) {
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
	inb, err := NewInbound([]User{{Name: "u", Password: "pw"}}, tlsConfig, direct.Outbound{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvLn.Close()
	go func() {
		for {
			c, err := srvLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = inb.HandleStream(context.Background(), connStream{c}, &endpoint.Metadata{}) }(c)
		}
	}()

	out, err := NewOutbound(Options{Server: srvLn.Addr().String(), Password: "pw", SNI: "localhost", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := out.DialStream(context.Background(), echoDst)
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	defer stream.Close()

	const msg = "hello through anytls session"
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
