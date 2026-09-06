package meter

import (
	"net/netip"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/core/cred"
)

// TestReapIdle 守 reaper Seam 3(§10 计量侧时间驱动 idle sweep):空闲超 idle 的活连接被回收、kill 触发;
// 未超 idle(刚建/刚活跃)的不被误踢。
func TestReapIdle(t *testing.T) {
	r := NewRegistry()
	id := r.IDForBill("alice@in")
	ip := netip.MustParseAddr("1.2.3.4")

	// ① 空闲连接被回收:开一条不 touch,等一小段后以短 idle sweep → 应回收 1 条并触发 kill。
	killed := make(chan struct{}, 1)
	_, done, ok := r.Open(id, ip, func() { killed <- struct{}{} })
	if !ok {
		t.Fatal("Open 应成功")
	}
	time.Sleep(30 * time.Millisecond)
	if n := r.ReapIdle(10*time.Millisecond, cred.ReasonIdleTimeout); n != 1 {
		t.Fatalf("ReapIdle 应回收 1 条空闲连接,得 %d", n)
	}
	select {
	case <-killed:
	case <-time.After(time.Second):
		t.Fatal("被回收连接的 kill 未触发")
	}
	done() // 模拟 kill→conn 关闭后的 release(扣 connsLive)
	if snap := r.Snapshot(); len(snap) > 0 && snap[0].ConnsLive != 0 {
		t.Fatalf("回收后 connsLive 应为 0,得 %d", snap[0].ConnsLive)
	}

	// ② 活跃连接不被误踢:刚开(lastActive≈now)立即以长 idle sweep → 0 回收。
	_, done2, ok2 := r.Open(id, ip, func() { t.Error("活跃连接被误踢") })
	if !ok2 {
		t.Fatal("Open2 应成功")
	}
	defer done2()
	if n := r.ReapIdle(time.Hour, cred.ReasonIdleTimeout); n != 0 {
		t.Fatalf("活跃连接不应被回收,却回收了 %d 条", n)
	}
	// ③ idle<=0 为空操作(防误配把所有连接扫掉)
	if n := r.ReapIdle(0, cred.ReasonIdleTimeout); n != 0 {
		t.Fatalf("idle<=0 应空操作,却回收了 %d 条", n)
	}
}
