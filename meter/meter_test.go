package meter

import (
	"net/netip"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/core/cred"
)

// TestMeterAccounting:Open→AddUp/AddDown→done 后 Snapshot 精确;connsTotal/Live 正确。
func TestMeterAccounting(t *testing.T) {
	r := NewRegistry()
	id := cred.ID(cred.UserBase + 7)

	m, done, ok := r.Open(id, netip.Addr{}, func() {})
	if !ok {
		t.Fatal("Open 应准入")
	}
	// 分多次加,跨越 drain 阈值。
	total := 0
	for i := 0; i < 5; i++ {
		m.AddUp(100000) // 5×100000 = 500000,超过 128KiB 阈值会 drain
		m.AddDown(200000)
		total++
	}
	// done 前:connsLive=1。
	snap := r.Snapshot()
	if len(snap) != 1 || snap[0].ID != uint64(id) {
		t.Fatalf("快照用户错:%+v", snap)
	}
	if snap[0].ConnsLive != 1 || snap[0].ConnsTotal != 1 {
		t.Fatalf("连接数错:live=%d total=%d", snap[0].ConnsLive, snap[0].ConnsTotal)
	}
	done() // flush 余量 + connsLive--

	snap = r.Snapshot()
	if snap[0].Up != 500000 || snap[0].Down != 1000000 {
		t.Fatalf("字节计量错:up=%d(want 500000) down=%d(want 1000000)", snap[0].Up, snap[0].Down)
	}
	if snap[0].ConnsLive != 0 || snap[0].ConnsTotal != 1 {
		t.Fatalf("收尾后连接数错:live=%d total=%d", snap[0].ConnsLive, snap[0].ConnsTotal)
	}

	// 第二条连接:total 递增,live 回到 1。
	_, done2, ok2 := r.Open(id, netip.Addr{}, func() {})
	_ = ok2
	snap = r.Snapshot()
	if snap[0].ConnsTotal != 2 || snap[0].ConnsLive != 1 {
		t.Fatalf("第二连接:total=%d(want 2) live=%d(want 1)", snap[0].ConnsTotal, snap[0].ConnsLive)
	}
	done2()
}

// TestDisableEnableKill:Disable 断老 + 拒新;Enable 恢复;KillConn 断单条。
func TestDisableEnableKill(t *testing.T) {
	r := NewRegistry()
	id := cred.ID(cred.UserBase + 3)

	killed1 := make(chan struct{}, 1)
	_, done1, ok := r.Open(id, netip.Addr{}, func() { killed1 <- struct{}{} })
	if !ok {
		t.Fatal("首连应准入")
	}

	// Disable:断老(1 条)+ 拒新。
	n, dok := r.Disable(id)
	if !dok || n != 1 {
		t.Fatalf("Disable 期望断 1 条,得 killed=%d ok=%v", n, dok)
	}
	select {
	case <-killed1: // killAll 异步 go k(),等它触发
	case <-time.After(time.Second):
		t.Fatal("Disable 未触发活连接的 kill")
	}
	done1() // 连接收尾

	// 拒新:停用期间 Open 返回 admitted=false。
	if _, _, ok := r.Open(id, netip.Addr{}, func() {}); ok {
		t.Fatal("停用期间 Open 应拒新")
	}

	// Enable:恢复准入。
	if !r.Enable(id) {
		t.Fatal("Enable 应成功")
	}
	m, done, ok := r.Open(id, netip.Addr{}, func() {})
	if !ok {
		t.Fatal("Enable 后应准入")
	}
	_ = m

	// KillConn:断这一条(用当前活连接的 connID)。
	snap := r.Snapshot()
	if snap[0].ConnsLive != 1 {
		t.Fatalf("Enable 后活连接应为 1,得 %d", snap[0].ConnsLive)
	}
	done()
}
