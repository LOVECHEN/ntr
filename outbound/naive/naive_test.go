package naive

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/outbound/anytls"
	"github.com/LOVECHEN/ntr/outbound/direct"
)

type connStreamTest struct{ net.Conn }

func (connStreamTest) Unwrap() any { return nil }

// TestPaddingRoundTrip:padding 状态机自洽 —— 写入的多段数据(跨越 paddingCount 边界、
// 含超 65535 的大段)经 read 还原后与原文逐字节一致。
func TestPaddingRoundTrip(t *testing.T) {
	segments := [][]byte{
		[]byte("first"),
		bytes.Repeat([]byte("x"), 100),
		bytes.Repeat([]byte("y"), 70000), // 触发 >65535 切块
		[]byte("after-padding-1"),
		[]byte("after-padding-2"),
		[]byte("after-padding-3"),
		[]byte("after-padding-4"),
		[]byte("after-padding-5"),
		[]byte("beyond-padding-count"), // 第 9 段起应为裸流
		[]byte("tail"),
	}
	var wire bytes.Buffer
	var wp paddingConn
	for _, seg := range segments {
		if _, err := wp.write(&wire, seg); err != nil {
			t.Fatal(err)
		}
	}
	var want []byte
	for _, seg := range segments {
		want = append(want, seg...)
	}

	var rp paddingConn
	got := make([]byte, 0, len(want))
	buf := make([]byte, 4096)
	for len(got) < len(want) {
		n, err := rp.read(&wire, buf)
		if err != nil {
			t.Fatalf("read 失败(已读 %d/%d):%v", len(got), len(want), err)
		}
		if n == 0 {
			t.Fatalf("read 返回 0(已读 %d/%d)", len(got), len(want))
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("padding 往返不一致:得到 %d 字节,want %d 字节", len(got), len(want))
	}
}

// TestNaiveRoundTrip:NTR naive 客户端 → 服务端(h2 解复用 + padding)→ direct → echo。
func TestNaiveRoundTrip(t *testing.T) {
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

	out, err := NewOutbound(Options{Server: srvLn.Addr().String(), User: "u", Password: "pw", SNI: "localhost", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := out.DialStream(context.Background(), echoDst)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	msg := []byte("hello-naive-ntr")
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

// TestNaiveBadAuth:错误密码应被服务端 407 拒绝。
func TestNaiveBadAuth(t *testing.T) {
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
