package trusttunnel

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/outbound/anytls"
	"github.com/LOVECHEN/ntr/outbound/direct"
)

// connStreamTest 把 net.Conn 抬成 link.Stream(测试用)。
type connStreamTest struct{ net.Conn }

func (connStreamTest) Unwrap() any { return nil }

// TestTrustTunnelRoundTrip:NTR trusttunnel 客户端(H2 CONNECT)→ 服务端(h2 解复用)→ direct → echo,
// 验证 TLS + Basic 认证 + CONNECT 双向流往返。
func TestTrustTunnelRoundTrip(t *testing.T) {
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

	tlsConfig, err := anytls.ServerTLSConfig("", "") // 临时自签
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
			go func(c net.Conn) { _ = inb.HandleStream(context.Background(), connStreamTest{c}, &endpoint.Metadata{}) }(c)
		}
	}()

	out, err := NewOutbound(Options{Server: srvLn.Addr().String(), User: "u", Password: "pw", SNI: "localhost", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := out.DialStream(context.Background(), echoDst)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	msg := []byte("hello-trusttunnel-ntr")
	if _, err := stream.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo 不匹配:得到 %q,want %q", buf, msg)
	}
}

// TestTrustTunnelBadAuth:错误密码应被服务端 407 拒绝(DialStream 失败)。
func TestTrustTunnelBadAuth(t *testing.T) {
	tlsConfig, err := anytls.ServerTLSConfig("", "")
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
			go func(c net.Conn) { _ = inb.HandleStream(context.Background(), connStreamTest{c}, &endpoint.Metadata{}) }(c)
		}
	}()

	out, err := NewOutbound(Options{Server: srvLn.Addr().String(), User: "u", Password: "wrong", SNI: "localhost", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := out.DialStream(context.Background(), addr.FromFqdn("example.com", 80)); err == nil {
		t.Fatal("期望错误密码被 407 拒,但 DialStream 成功了")
	}
}
