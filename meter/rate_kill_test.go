package meter

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/core/cred"
)

// TestSampleRates:每秒采样做差得瞬时 bps,不动单调计数。
func TestSampleRates(t *testing.T) {
	reg := NewRegistry()
	id := reg.IDForBill("alice@in")
	m, done, ok := reg.Open(id, netip.MustParseAddr("10.0.0.1"), func() {})
	if !ok {
		t.Fatal("Open")
	}
	defer done()
	// 灌 300000 上行 / 120000 下行(直接走 drain 到 Cell)。
	for range 3 {
		m.AddUp(drainThreshold) // 每次 drain 一次
	}
	m.Flush()
	up0 := reg.Snapshot()[0].Up
	reg.sampleRates(time.Second) // 第一次:lastUp=0 → rate = 全量;设 last=up0
	st := reg.Snapshot()[0]
	if st.RateUp == 0 || st.RateUp != up0 {
		t.Fatalf("首窗速率应=本窗字节(间隔1s):rateUp=%d up=%d", st.RateUp, up0)
	}
	// 第二窗:无新增 → 速率归零;单调计数不变。
	reg.sampleRates(time.Second)
	st = reg.Snapshot()[0]
	if st.RateUp != 0 {
		t.Fatalf("无新增流量速率应归零,实为 %d", st.RateUp)
	}
	if st.Up != up0 {
		t.Fatalf("单调计数不应被采样改动:%d != %d", st.Up, up0)
	}
}

// TestKillIP:只断匹配源 IP 的连接,其它源不动。
func TestKillIP(t *testing.T) {
	reg := NewRegistry()
	id := reg.IDForBill("bob@in")
	var killedA, killedB atomic.Bool
	if _, _, ok := reg.Open(id, netip.MustParseAddr("1.1.1.1"), func() { killedA.Store(true) }); !ok {
		t.Fatal("open A")
	}
	if _, _, ok := reg.Open(id, netip.MustParseAddr("2.2.2.2"), func() { killedB.Store(true) }); !ok {
		t.Fatal("open B")
	}
	n := reg.KillIP(id, netip.MustParseAddr("1.1.1.1"))
	if n != 1 {
		t.Fatalf("应断 1 条(源 1.1.1.1),实为 %d", n)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !killedA.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	if !killedA.Load() {
		t.Fatal("源 1.1.1.1 应被断")
	}
	if killedB.Load() {
		t.Fatal("源 2.2.2.2 不应被断")
	}
	// 未知源 / 未知凭据 → 0。
	if reg.KillIP(id, netip.MustParseAddr("9.9.9.9")) != 0 {
		t.Fatal("未知源应返回 0")
	}
	if reg.KillIP(cred.UserBase+999, netip.MustParseAddr("1.1.1.1")) != 0 {
		t.Fatal("未知凭据应返回 0")
	}
}

// TestRejectedVisibility:max-ips 触顶的拒绝数进 Snapshot(§6.4.2 可见性:触顶绝不静默)。
func TestRejectedVisibility(t *testing.T) {
	reg := NewRegistry()
	id := reg.IDForBill("carol@in")
	reg.SetLimits(id, Limits{MaxIPs: 1})
	_, done1, ok := reg.Open(id, netip.MustParseAddr("1.1.1.1"), func() {})
	if !ok {
		t.Fatal("首个源应放行")
	}
	defer done1()
	if _, _, ok := reg.Open(id, netip.MustParseAddr("2.2.2.2"), func() {}); ok {
		t.Fatal("第二个源超 max-ips=1 应被拒")
	}
	var st *UserStat
	for _, s := range reg.Snapshot() {
		if s.Bill == "carol@in" {
			s := s
			st = &s
		}
	}
	if st == nil || st.RejectedIP != 1 {
		t.Fatalf("max-ips 触顶拒绝数应可见=1,实为 %+v", st)
	}
}
