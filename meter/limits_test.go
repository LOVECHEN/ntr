package meter

import (
	"net/netip"
	"testing"

	"github.com/LOVECHEN/ntr/core/cred"
)

// TestMaxConns:第 N+1 条连接被拒,rejected 计数;释放后又可接。
func TestMaxConns(t *testing.T) {
	r := NewRegistry()
	id := cred.ID(cred.UserBase + 11)
	r.SetLimits(id, Limits{MaxConns: 2})
	ip := netip.MustParseAddr("203.0.113.9")

	_, d1, ok1 := r.Open(id, ip, func() {})
	_, d2, ok2 := r.Open(id, ip, func() {})
	_, _, ok3 := r.Open(id, ip, func() {}) // 第 3 条 → 拒
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("max-conns=2:期望前 2 通、第 3 拒,得 %v %v %v", ok1, ok2, ok3)
	}
	if snap := r.Snapshot(); snap[0].Rejected != 1 || snap[0].ConnsLive != 2 {
		t.Fatalf("触顶计数错:rejected=%d live=%d", snap[0].Rejected, snap[0].ConnsLive)
	}
	d1() // 释放一条
	if _, d4, ok4 := r.Open(id, ip, func() {}); !ok4 {
		t.Fatal("释放后应可再接")
	} else {
		d4()
	}
	d2()
}

// TestMaxIPs:不同源 IP 超限被拒;同 IP 多连接不占新槽。
func TestMaxIPs(t *testing.T) {
	r := NewRegistry()
	id := cred.ID(cred.UserBase + 12)
	r.SetLimits(id, Limits{MaxIPs: 2})
	a := netip.MustParseAddr("198.51.100.1")
	b := netip.MustParseAddr("198.51.100.2")
	c := netip.MustParseAddr("198.51.100.3")

	_, _, ok1 := r.Open(id, a, func() {})
	_, _, ok1b := r.Open(id, a, func() {}) // 同 IP a 再来:不占新槽
	_, _, ok2 := r.Open(id, b, func() {})
	_, _, ok3 := r.Open(id, c, func() {}) // 第 3 个不同 IP → 拒
	if !ok1 || !ok1b || !ok2 || ok3 {
		t.Fatalf("max-ips=2:期望 a/a/b 通、c 拒,得 %v %v %v %v", ok1, ok1b, ok2, ok3)
	}
}
