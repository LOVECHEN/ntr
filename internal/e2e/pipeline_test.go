// Package e2e 端到端验证"协议只是插件":一条真实字节从 snell 客户端穿过统一的
// proxy.Server 接口、经协议无关的 relay + direct 出站,打到 echo 靶机再原路返回。
//
// ★关键:本测试的服务端侧路径(ServerHandshake → relay.Relay → direct.DialStream)
// 完全不 import snell、不看协议类型 —— snell 只在①构造插件 ②扮演客户端 两处出现。
// 这就是核心零协议 switch 的可执行证据。
package e2e

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/relay"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/proto/snell"
)

// TestSnellPipelineAgnostic:snell 客户端 → proxy.Server → relay → direct → echo,全通。
func TestSnellPipelineAgnostic(t *testing.T) {
	// 1) echo 靶机(真实 TCP,direct 出站会拨到它)。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()
	dst := addr.FromIPPort(ln.Addr().(*net.TCPAddr).AddrPort())

	// 2) 客户端<->服务端传输层(内存管道当"网络")。
	cliConn, srvConn := net.Pipe()
	ctx := context.Background()
	psk := []byte("ntr-e2e-snell-psk-0123456789abcd")

	built, err := snell.Build(ctx, snell.Config{PSK: psk}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plugin := built // *snell.Proxy:同时是 proxy.Server 与 proxy.Client

	const msg = "ping through the agnostic pipeline"
	clientDone := make(chan error, 1)
	go func() {
		defer cliConn.Close() // 收尾必关,让服务端侧 relay 见 EOF 拆链
		cs, err := plugin.(proxy.Client).ClientHandshake(ctx, pipeStream{cliConn}, psk, dst)
		if err != nil {
			clientDone <- err
			return
		}
		if _, err := cs.Write([]byte(msg)); err != nil {
			clientDone <- err
			return
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(cs, buf); err != nil {
			clientDone <- err
			return
		}
		if string(buf) != msg {
			clientDone <- errMismatch(buf)
			return
		}
		clientDone <- nil
	}()

	// 3) 服务端侧:全程只认 proxy.Server / link.Stream / endpoint.Outbound,零协议特判。
	stream, req, err := plugin.(proxy.Server).ServerHandshake(ctx, pipeStream{srvConn}, ambientAuth{})
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst.String() != dst.String() {
		t.Fatalf("server decoded dst = %s, want %s", req.Dst.String(), dst.String())
	}
	if req.Cred.ID != cred.Ambient {
		t.Fatalf("cred = %d, want Ambient", req.Cred.ID)
	}

	up, err := direct.Outbound{}.DialStream(ctx, req.Dst)
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.Relay(stream, up); err != nil {
		t.Fatalf("relay: %v", err)
	}

	if err := <-clientDone; err != nil {
		t.Fatalf("client: %v", err)
	}
}

// pipeStream 把 net.Conn 抬成 link.Stream。
type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

// ambientAuth:端口 PSK 已鉴权,用户身份未登记 → 一律归 Ambient。
type ambientAuth struct{}

func (ambientAuth) Auth(_ string, _ []byte) (cred.Ref, bool) {
	return cred.Ref{ID: cred.Ambient}, true
}

type errMismatch []byte

func (e errMismatch) Error() string { return "echo mismatch: got " + string(e) }
