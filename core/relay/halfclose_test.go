package relay

import (
	"io"
	"net"
	"testing"
	"time"
)

// tcpStream 把 *net.TCPConn 抬成 link.Stream 并透出其 CloseWrite/SetReadDeadline 能力(GetCapability 命中)。
type tcpStream struct{ *net.TCPConn }

func (tcpStream) Unwrap() any { return nil }

// tcpPair 建一对已连接的 *net.TCPConn(本地环回)。
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		c   *net.TCPConn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- res{nil, err}
			return
		}
		ch <- res{c.(*net.TCPConn), nil}
	}()
	dc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	return dc.(*net.TCPConn), r.c
}

// TestRelayHalfClose 守 reaper Seam 2(§10 半关):一端 CloseWrite(发 FIN)后 —— ① FIN 传到对端;
// ② 反向仍能投递;③ 反向静默过 halfCloseIdle 后整条被回收(Relay 返回),不永久钉住。
func TestRelayHalfClose(t *testing.T) {
	SetHalfCloseIdle(150 * time.Millisecond) // 缩短尾部 idle 便于测试
	defer SetHalfCloseIdle(0)                // 复位回默认

	a, aPeer := tcpPair(t)
	b, bPeer := tcpPair(t)
	defer aPeer.Close()
	defer bPeer.Close()

	done := make(chan error, 1)
	go func() { done <- Relay(tcpStream{a}, tcpStream{b}) }()

	// 正向仍通:aPeer → a→b → bPeer
	if _, err := aPeer.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(bPeer, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("正向 = %q err=%v, want hi", buf, err)
	}

	// aPeer 半关(只关写、发 FIN):a 读到 EOF → Relay 应对 b 端 CloseWrite 把 FIN 传给 bPeer。
	if err := aPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// ① bPeer 应读到 EOF(FIN 传到了),而非永久阻塞。
	_ = bPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := bPeer.Read(make([]byte, 4)); err != io.EOF {
		t.Fatalf("FIN 未传到 bPeer:期望 EOF,得 %v", err)
	}
	// ② 反向仍能投递:bPeer → b→a → aPeer(aPeer 读侧仍开)。
	_ = bPeer.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := bPeer.Write([]byte("yo")); err != nil {
		t.Fatal(err)
	}
	_ = aPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	rb := make([]byte, 2)
	if _, err := io.ReadFull(aPeer, rb); err != nil || string(rb) != "yo" {
		t.Fatalf("半关后反向 = %q err=%v, want yo(半关应保留反向)", rb, err)
	}
	// ③ bPeer 此后静默 → 过 halfCloseIdle 后 b 的 ReadDeadline 触发 → 反向结束 → Relay 返回。
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("半关后反向 idle 未回收:Relay 未在 halfCloseIdle 后返回")
	}
}

// TestRelayHalfCloseFallback 守诚实降级:两端探不到 CloseWrite 能力(net.Pipe)时,首方向 EOF 退回「关两端」,
// 不挂起。
func TestRelayHalfCloseFallback(t *testing.T) {
	aP, a := net.Pipe()
	bP, b := net.Pipe()
	defer bP.Close()
	done := make(chan error, 1)
	go func() { done <- Relay(pipeStream{a}, pipeStream{b}) }()
	_ = aP.Close() // a 读 EOF;pipeStream 无 CloseWrite → 退回关两端
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("无 CloseWrite 能力时未退回关两端,Relay 挂起")
	}
}
