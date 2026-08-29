package socks

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/link"
)

// TestClientServerSelfLoop:NTR SOCKS5 客户端(ClientHandshake)↔ NTR SOCKS5 服务端
// (ServerHandshake)经真 TCP 往返(net.Pipe 同步会死锁,多次读写用真 socket)。
// 验客户端问候/CONNECT 与服务端握手线级自洽,payload 双向不破。
func TestClientServerSelfLoop(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	p := &Proxy{}
	target := addr.FromFqdn("example.com", 443)
	srvDone := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvDone <- err
			return
		}
		defer c.Close()
		hs, req, err := p.ServerHandshake(context.Background(), pipeStream{c}, authStub{})
		if err != nil {
			srvDone <- err
			return
		}
		if req.Dst.Fqdn != "example.com" || req.Dst.Port != 443 {
			srvDone <- io.ErrUnexpectedEOF
			return
		}
		// 服务端 echo:把握手后 stream 上收到的 payload 原样回写。
		buf := make([]byte, 64)
		n, _ := hs.Read(buf)
		_, _ = hs.Write(buf[:n])
		srvDone <- nil
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	var below link.Stream = pipeStream{c}
	hs, err := p.ClientHandshake(context.Background(), below, nil, target)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	msg := []byte("hello-socks-selfloop")
	if _, err := hs.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(hs, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("payload 不符:got %q want %q", got, msg)
	}
	if err := <-srvDone; err != nil {
		t.Fatalf("服务端: %v", err)
	}
}

// TestClientUserPassNegotiation:客户端在 key 非空时提供 user/pass,跑 RFC1929 子协商。
// 用一个最小的假 SOCKS 服务器:选 0x02,读 user/pass,回成功,再读 CONNECT 回 success。
func TestClientUserPassNegotiation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotUser := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// 问候:VER NMETHODS METHODS
		h := make([]byte, 2)
		_, _ = io.ReadFull(c, h)
		methods := make([]byte, h[1])
		_, _ = io.ReadFull(c, methods)
		_, _ = c.Write([]byte{version, methodUserPass}) // 选 user/pass
		// RFC1929:VER ULEN USER PLEN PASS
		var uh [2]byte
		_, _ = io.ReadFull(c, uh[:])
		user := make([]byte, uh[1])
		_, _ = io.ReadFull(c, user)
		var ph [1]byte
		_, _ = io.ReadFull(c, ph[:])
		pass := make([]byte, ph[0])
		_, _ = io.ReadFull(c, pass)
		gotUser <- string(user) + ":" + string(pass)
		_, _ = c.Write([]byte{authVersion, 0x00}) // 认证成功
		// CONNECT:VER CMD RSV ATYP ADDR PORT
		req := make([]byte, 4)
		_, _ = io.ReadFull(c, req)
		_, _ = readAddr(c, req[3])
		_, _ = c.Write(reply(0x00))
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	p := &Proxy{}
	if _, err := p.ClientHandshake(context.Background(), pipeStream{c}, []byte("alice:secret"), addr.FromFqdn("t.com", 80)); err != nil {
		t.Fatalf("ClientHandshake(user/pass): %v", err)
	}
	if u := <-gotUser; u != "alice:secret" {
		t.Fatalf("服务端收到的凭据不符:%q", u)
	}
}
