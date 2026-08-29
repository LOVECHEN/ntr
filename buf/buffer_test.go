package buf

import "testing"

func TestHeadroomTailroom(t *testing.T) {
	b := New()
	defer b.Release()
	if b.Len() != 0 {
		t.Fatalf("new buffer len = %d, want 0", b.Len())
	}
	if b.Headroom() != DefaultHeadroom {
		t.Fatalf("headroom = %d, want %d", b.Headroom(), DefaultHeadroom)
	}

	if _, err := b.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := string(b.Bytes()); got != "hello" {
		t.Fatalf("payload = %q, want hello", got)
	}

	// 向前扩写头 —— 不搬载荷,只切片重定位。
	copy(b.ExtendHeader(3), []byte("HDR"))
	if got := string(b.Bytes()); got != "HDRhello" {
		t.Fatalf("after ExtendHeader = %q, want HDRhello", got)
	}

	// 向后扩写尾。
	copy(b.ExtendTail(2), []byte("TL"))
	if got := string(b.Bytes()); got != "HDRhelloTL" {
		t.Fatalf("after ExtendTail = %q, want HDRhelloTL", got)
	}

	// Advance 剥头 / Truncate 截尾。
	b.Advance(3) // 剥掉 "HDR"
	if got := string(b.Bytes()); got != "helloTL" {
		t.Fatalf("after Advance = %q, want helloTL", got)
	}
	b.Truncate(5)
	if got := string(b.Bytes()); got != "hello" {
		t.Fatalf("after Truncate = %q, want hello", got)
	}
}

func TestShortBuffer(t *testing.T) {
	b := New()
	defer b.Release()
	big := make([]byte, DefaultSize) // 必然超出(headroom 已占 512)
	if _, err := b.Write(big); err != ErrShortBuffer {
		t.Fatalf("err = %v, want ErrShortBuffer", err)
	}
}

// TestZeroAlloc 保证池化取还(New→Release 复用)在稳态不产生分配 —— 中继路径
// 零分配纪律的最小守卫(承 §3.6bis.4 的 AllocsPerRun 门禁思想)。
func TestZeroAlloc(t *testing.T) {
	payload := []byte("some payload bytes for the relay loop")
	allocs := testing.AllocsPerRun(200, func() {
		b := New()
		_, _ = b.Write(payload)
		_ = b.Bytes()
		b.Release()
	})
	if allocs > 0 {
		t.Fatalf("pooled New/Release allocated %v times, want 0", allocs)
	}
}
