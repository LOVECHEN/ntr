package meter

import (
	"net/netip"
	"testing"

	"github.com/LOVECHEN/ntr/core/cred"
)

// TestIDForBill_StableAndUnique:同 bill 恒同 id(幂等、跨 reload 复用的前提);不同 bill 不撞;
// 从 UserBase+1 起不占 Unmatched/Ambient;反查与标签一致。
func TestIDForBill_StableAndUnique(t *testing.T) {
	r := NewRegistry()
	a := r.IDForBill("alice@vless-in")
	if a != cred.UserBase+1 {
		t.Fatalf("首个 id 应为 UserBase+1,实为 %d", a)
	}
	if r.IDForBill("alice@vless-in") != a {
		t.Fatal("同 bill 应恒同 id")
	}
	b := r.IDForBill("bob@vless-in")
	if b == a || b != a+1 {
		t.Fatalf("新 bill 应取下一个空位: a=%d b=%d", a, b)
	}
	if id, ok := r.IDByBill("bob@vless-in"); !ok || id != b {
		t.Fatalf("反查错: %d %v", id, ok)
	}
	if _, ok := r.IDByBill("nobody"); ok {
		t.Fatal("未登记 bill 反查应 false")
	}
	if r.Bill(a) != "alice@vless-in" || r.Bill(cred.Ambient) != "" {
		t.Fatalf("标签错: %q / %q", r.Bill(a), r.Bill(cred.Ambient))
	}
	// Snapshot 带 bill 标签
	r.cell(a)
	for _, s := range r.Snapshot() {
		if s.ID == uint64(a) && s.Bill != "alice@vless-in" {
			t.Fatalf("Snapshot 应带 bill 标签: %+v", s)
		}
	}
}

// TestSetLimitsShared_MaxConnsAcrossCells:同一 user 两个口(两个 BillID/Cell)共享 max-conns=1 ——
// 在 a 口占住一条后,b 口的接入必须被拒(合计语义);释放后恢复。每 Cell 的 connsLive 统计仍各自准确。
func TestSetLimitsShared_MaxConnsAcrossCells(t *testing.T) {
	r := NewRegistry()
	a := r.IDForBill("alice@a")
	b := r.IDForBill("alice@b")
	r.SetLimitsShared([]cred.ID{a, b}, Limits{MaxConns: 1})
	src := netip.MustParseAddr("10.0.0.1")

	_, done1, ok := r.Open(a, src, func() {})
	if !ok {
		t.Fatal("第一条接入应通过")
	}
	if _, _, ok := r.Open(b, src, func() {}); ok {
		t.Fatal("另一口的第二条接入应被合计 max-conns=1 拒绝")
	}
	if r.cell(a).connsLive.Load() != 1 || r.cell(b).connsLive.Load() != 0 {
		t.Fatalf("每 Cell 统计应各自准确: a=%d b=%d", r.cell(a).connsLive.Load(), r.cell(b).connsLive.Load())
	}
	done1()
	_, done3, ok := r.Open(b, src, func() {})
	if !ok {
		t.Fatal("释放后另一口应能接入")
	}
	done3()
	if r.cell(a).rejectedConns.Load() != 0 || r.cell(b).rejectedConns.Load() != 1 {
		t.Fatalf("被拒计数应记在被拒的那口: a=%d b=%d", r.cell(a).rejectedConns.Load(), r.cell(b).rejectedConns.Load())
	}
}

// TestSetLimitsShared_MaxIPsAcrossCells:共享 max-ips=1:a 口用 IP1 在线时,b 口来 IP2 应被拒(同一人的 IP 集合合计)。
func TestSetLimitsShared_MaxIPsAcrossCells(t *testing.T) {
	r := NewRegistry()
	a := r.IDForBill("alice@a")
	b := r.IDForBill("alice@b")
	r.SetLimitsShared([]cred.ID{a, b}, Limits{MaxIPs: 1})
	ip1, ip2 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	_, done1, ok := r.Open(a, ip1, func() {})
	if !ok {
		t.Fatal("IP1 首次接入应通过")
	}
	if _, _, ok := r.Open(b, ip2, func() {}); ok {
		t.Fatal("另一口的 IP2 应被合计 max-ips=1 拒绝")
	}
	_, done2, ok := r.Open(b, ip1, func() {})
	if !ok {
		t.Fatal("同 IP1 在另一口应通过(同一 IP 不占新名额)")
	}
	done1()
	done2()
}
