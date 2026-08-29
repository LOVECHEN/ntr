package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/outbound/direct"
)

// genHostKey 生成一把 ed25519 host 私钥(OpenSSH PEM)供测试。
func genHostKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

// TestSshRoundTrip:NTR ssh 客户端(direct-tcpip channel)→ NTR ssh 服务端(channel 解复用)
// → direct → echo,验证密码认证 + channel 收发往返。
func TestSshRoundTrip(t *testing.T) {
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

	inb, err := NewInbound([]User{{Name: "u", Password: "pw"}}, genHostKey(t), direct.Outbound{}, nil)
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

	out, err := NewOutbound(Options{Server: srvLn.Addr().String(), User: "u", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := out.DialStream(context.Background(), echoDst)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	msg := []byte("hello-ssh-ntr")
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

// TestSshBadPassword:错误密码应被服务端拒绝(DialStream 失败)。
func TestSshBadPassword(t *testing.T) {
	inb, err := NewInbound([]User{{Name: "u", Password: "pw"}}, genHostKey(t), direct.Outbound{}, nil)
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

	out, err := NewOutbound(Options{Server: srvLn.Addr().String(), User: "u", Password: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := out.DialStream(context.Background(), addr.FromFqdn("example.com", 80)); err == nil {
		t.Fatal("期望错误密码被拒,但 DialStream 成功了")
	}
}
