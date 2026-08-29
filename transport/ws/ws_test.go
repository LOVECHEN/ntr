package ws

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/LOVECHEN/ntr/core/link"
)

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

// wrapPair 在 net.Pipe 上完成 WS 握手,返回客户端/服务端两条承载 stream。
func wrapPair(t *testing.T) (link.Stream, link.Stream, func()) {
	t.Helper()
	c, s := net.Pipe()
	ctx := context.Background()
	tr, err := Build(ctx, Config{Path: "/x", Host: "h.example"}, nil)
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
		ss, err := trans.ServerWrap(ctx, pipeStream{s})
		ch <- res{ss, err}
	}()
	cs, err := trans.ClientWrap(ctx, pipeStream{c})
	if err != nil {
		t.Fatalf("ClientWrap: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("ServerWrap: %v", r.err)
	}
	return cs, r.ss, func() { c.Close(); s.Close() }
}

// TestWSRoundTrip:三档 payload 长度覆盖 7-bit / 16-bit / 64-bit 三种帧长编码,双向验证。
func TestWSRoundTrip(t *testing.T) {
	for _, size := range []int{5, 125, 126, 4096, 70000} {
		cs, ss, done := wrapPair(t)
		// 客户端 → 服务端(客户端帧带掩码)
		want := bytes.Repeat([]byte{0xA7}, size)
		go func() {
			if _, err := cs.Write(want); err != nil {
				t.Errorf("size=%d client write: %v", size, err)
			}
		}()
		got := make([]byte, size)
		if _, err := io.ReadFull(ss, got); err != nil {
			t.Fatalf("size=%d server read: %v", size, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("size=%d c→s 不一致", size)
		}
		// 服务端 → 客户端(服务端帧不掩码)
		want2 := bytes.Repeat([]byte{0x5C}, size)
		go func() {
			if _, err := ss.Write(want2); err != nil {
				t.Errorf("size=%d server write: %v", size, err)
			}
		}()
		got2 := make([]byte, size)
		if _, err := io.ReadFull(cs, got2); err != nil {
			t.Fatalf("size=%d client read: %v", size, err)
		}
		if !bytes.Equal(got2, want2) {
			t.Fatalf("size=%d s→c 不一致", size)
		}
		done()
	}
}

// TestWSMultiWriteReassembly:连续多次小写入被对端顺序拼回(分帧对上层透明)。
func TestWSMultiWriteReassembly(t *testing.T) {
	cs, ss, done := wrapPair(t)
	defer done()
	chunks := []string{"hello", "-", "world", "-", "42"}
	go func() {
		for _, c := range chunks {
			if _, err := cs.Write([]byte(c)); err != nil {
				t.Errorf("write %q: %v", c, err)
				return
			}
		}
	}()
	want := "hello-world-42"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(ss, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("拼回 = %q, want %q", got, want)
	}
}

// TestWSHandshakeReject:非法 Accept / 缺 key 应握手失败(不静默放行)。
func TestWSHandshakeReject(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()
	// 服务端侧塞一个假的 HTTP 服务器:回错误的 Accept。
	go func() {
		br := make([]byte, 512)
		_, _ = s.Read(br)
		_, _ = s.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: WRONG\r\n\r\n"))
	}()
	tr, _ := Build(ctx, Config{Path: "/", Host: "h"}, nil)
	if _, err := tr.(*Transport).ClientWrap(ctx, pipeStream{c}); err == nil {
		t.Fatal("错误的 Sec-WebSocket-Accept 应被拒绝")
	}
}

// splitConn 把每次 Write 拆成逐字节子写,放大并发写的交错窗口。
type splitConn struct{ net.Conn }

func (splitConn) Unwrap() any { return nil }

func (s splitConn) Write(p []byte) (int, error) {
	for i := range p {
		if _, err := s.Conn.Write(p[i : i+1]); err != nil {
			return i, err
		}
	}
	return len(p), nil
}

// TestWSConcurrentWriteIntegrity:客户端下层逐字节拆分 + 20 并发写各 100 字节帧,服务端应能完整
// 解出 2000 字节(无帧交错)。缺 wmu 串行化时字节会交错 → readFrame 解码报错 → ReadFull 失败。
func TestWSConcurrentWriteIntegrity(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx := context.Background()
	tr, _ := Build(ctx, Config{Path: "/", Host: "h"}, nil)
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
	cs, err := trans.ClientWrap(ctx, splitConn{c}) // 客户端下层逐字节写
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	const n, sz = 20, 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cs.Write(bytes.Repeat([]byte{0xC3}, sz)); err != nil {
				t.Errorf("write: %v", err)
			}
		}()
	}
	got := make([]byte, n*sz)
	if _, err := io.ReadFull(r.ss, got); err != nil {
		t.Fatalf("并发写帧交错导致解码失败(mutex 失效?):%v", err)
	}
	wg.Wait()
	for _, b := range got {
		if b != 0xC3 {
			t.Fatal("payload 被污染")
		}
	}
}

// TestWSRejectHugeFrame:64-bit length 超过上限的帧头应被拒(防 OOM),不触发巨型 make。
func TestWSRejectHugeFrame(t *testing.T) {
	hdr := []byte{0x82, 127, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} // len=2^64-1
	c := &wsConn{br: bufio.NewReader(bytes.NewReader(hdr))}
	if _, _, err := c.readFrame(); err == nil {
		t.Fatal("超大帧应被拒绝")
	}
}
