package block

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
)

// TestReject:默认模式 DialStream/DialPacket 立即返回 ErrBlocked。
func TestReject(t *testing.T) {
	o := Outbound{Drop: false}
	if _, err := o.DialStream(context.Background(), addr.FromFqdn("x", 80)); !errors.Is(err, ErrBlocked) {
		t.Fatalf("DialStream 期望 ErrBlocked,得 %v", err)
	}
	if _, err := o.DialPacket(context.Background(), addr.FromFqdn("x", 80)); !errors.Is(err, ErrBlocked) {
		t.Fatalf("DialPacket 期望 ErrBlocked,得 %v", err)
	}
}

// TestDropWriteDiscardReadBlocks:drop 模式写被丢弃(佯成功)、读阻塞到 Close。
func TestDropWriteDiscardReadBlocks(t *testing.T) {
	o := Outbound{Drop: true}
	s, err := o.DialStream(context.Background(), addr.FromFqdn("x", 80))
	if err != nil {
		t.Fatalf("drop DialStream 不应报错:%v", err)
	}
	n, err := s.Write([]byte("swallowed"))
	if err != nil || n != len("swallowed") {
		t.Fatalf("写应被丢弃且佯成功,得 n=%d err=%v", n, err)
	}

	done := make(chan struct{})
	go func() {
		_, _ = s.Read(make([]byte, 4)) // 应阻塞到 Close
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Read 不应在 Close 前返回")
	case <-time.After(100 * time.Millisecond):
	}
	_ = s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close 后 Read 应立即返回")
	}
}

// TestDropPacket:drop 模式 WritePacket 丢弃、ReadPacket 阻塞到 Close。
func TestDropPacket(t *testing.T) {
	o := Outbound{Drop: true}
	pc, err := o.DialPacket(context.Background(), addr.FromFqdn("x", 80))
	if err != nil {
		t.Fatalf("drop DialPacket 不应报错:%v", err)
	}
	b := buf.New()
	defer b.Release()
	_, _ = b.Write([]byte("gone"))
	if err := pc.WritePacket(b, addr.Socksaddr{}); err != nil {
		t.Fatalf("WritePacket 应丢弃佯成功,得 %v", err)
	}
	_ = pc.Close()
	if _, err := pc.ReadPacket(b); err == nil {
		t.Fatal("Close 后 ReadPacket 应报错")
	}
}
