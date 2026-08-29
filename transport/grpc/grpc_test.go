package grpc

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
)

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

// TestHunkFraming:gRPC 消息帧 + Hunk protobuf 手写编解码往返(覆盖 0 / varint 边界 127→128 / 大帧)。
func TestHunkFraming(t *testing.T) {
	for _, size := range []int{0, 1, 127, 128, 16383, 16384, 70000} {
		var buf bytes.Buffer
		data := bytes.Repeat([]byte{0x5A}, size)
		if err := writeHunk(&buf, data); err != nil {
			t.Fatalf("size=%d writeHunk: %v", size, err)
		}
		got, err := readHunk(bufio.NewReader(&buf))
		if err != nil {
			t.Fatalf("size=%d readHunk: %v", size, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("size=%d 往返不一致(got %d 字节)", size, len(got))
		}
	}
}

// TestGrpcRoundTrip:在真实回环 TCP 上跑完整 HTTP/2 + gRPC 双向流(客户端先写,验证不因等响应头死锁)。
func TestGrpcRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx := context.Background()
	tr, err := Build(ctx, Config{ServiceName: "GunService"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	trans := tr.(*Transport)

	type res struct {
		ss  link.Stream
		err error
	}
	ch := make(chan res, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- res{nil, err}
			return
		}
		ss, err := trans.ServerWrap(ctx, pipeStream{conn})
		ch <- res{ss, err}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cs, err := trans.ClientWrap(ctx, pipeStream{c})
	if err != nil {
		t.Fatal(err)
	}
	// 客户端先写(grpc 服务端常在收到首帧后才回响应头 —— 验证 async RoundTrip 不死锁)。
	go func() { _, _ = cs.Write([]byte("REQ")) }()

	r := <-ch
	if r.err != nil {
		t.Fatalf("ServerWrap: %v", r.err)
	}
	ss := r.ss
	got := make([]byte, 3)
	if _, err := io.ReadFull(ss, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "REQ" {
		t.Fatalf("server got %q", got)
	}
	go func() { _, _ = ss.Write([]byte("RESP")) }()
	got2 := make([]byte, 4)
	if _, err := io.ReadFull(cs, got2); err != nil {
		t.Fatal(err)
	}
	if string(got2) != "RESP" {
		t.Fatalf("client got %q", got2)
	}
}

// TestGrpcRejectHugeMsg:5 字节前缀声明超大 msgLen 应被拒(防 OOM),不触发巨型 make。
func TestGrpcRejectHugeMsg(t *testing.T) {
	prefix := []byte{0, 0xFF, 0xFF, 0xFF, 0xFF} // msgLen = 4GiB-1
	if _, err := readHunk(bufio.NewReader(bytes.NewReader(prefix))); err == nil {
		t.Fatal("超大消息应被拒绝")
	}
}

// TestClientCloseBeforeRead:客户端流在首次 Read 前 Close,应立即返回、后续 Read 得干净错误,
// 且后台 RoundTrip goroutine 能自行清理 resp.Body(不泄漏、不死锁)。
func TestClientCloseBeforeRead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx := context.Background()
	tr, _ := Build(ctx, Config{ServiceName: "GunService"}, nil)
	trans := tr.(*Transport)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		ss, err := trans.ServerWrap(ctx, pipeStream{conn})
		if err == nil {
			// 服务端读一帧再挂着,制造"响应头已回但客户端未 Read"的窗口
			go func() { _, _ = ss.Read(make([]byte, 16)) }()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cs, err := trans.ClientWrap(ctx, pipeStream{c})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = cs.Write([]byte("hi")) // 触发服务端回响应头,resp 可能已在 respCh 待取
	done := make(chan struct{})
	go func() {
		_ = cs.Close()
		_, rerr := cs.Read(make([]byte, 4))
		if rerr == nil {
			t.Errorf("Close 后 Read 应返回错误")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close-before-Read 死锁(泄漏协调有误)")
	}
}

// TestHostAliasForAuthority:grpc 应接受 host 作为 authority 的别名(与 ws/httpupgrade 一致)。
func TestHostAliasForAuthority(t *testing.T) {
	node := &spec.Node{Kind: spec.KindMap, Map: map[string]*spec.Node{
		"host": spec.Scalar("cdn.example.com"),
	}}
	cfg, err := Parse(node)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Authority != "cdn.example.com" {
		t.Fatalf("host 别名未生效:authority=%q", cfg.Authority)
	}
	if cfg.ServiceName != "GunService" {
		t.Fatalf("service-name 缺省应为 GunService,得 %q", cfg.ServiceName)
	}
}
