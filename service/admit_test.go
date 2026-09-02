package service

import (
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/meter"
)

type closeSpy struct{ closed bool }

func (c *closeSpy) Close() error { c.closed = true; return nil }

// TestAdmitterGateOnly:无计量、有全局闸 —— max-conns 满则拒新(并关 closers),释放后可再进。
func TestAdmitterGateOnly(t *testing.T) {
	a := &Admitter{Gates: []*meter.Gate{meter.NewGate(1, 0)}}
	m1, rel1, err := a.AdmitConn(cred.Ambient, addr.Socksaddr{})
	if err != nil {
		t.Fatalf("首条应放行: %v", err)
	}
	if m1 == nil {
		t.Fatal("gate-only 应返回 gate 计量器(非 nil)")
	}
	sp := &closeSpy{}
	if _, _, err := a.AdmitConn(cred.Ambient, addr.Socksaddr{}, sp); err == nil {
		t.Fatal("第二条超 max-conns=1 应被拒")
	}
	if !sp.closed {
		t.Fatal("被拒时 closers 应被关闭")
	}
	rel1()
	_, rel3, err := a.AdmitConn(cred.Ambient, addr.Socksaddr{})
	if err != nil {
		t.Fatalf("释放后应可再进: %v", err)
	}
	rel3()
}

// TestAdmitterMeterPath:开计量 —— Admit 登记到 who 的 Cell、返回计量流,release 后 connsLive 归零。
func TestAdmitterMeterPath(t *testing.T) {
	reg := meter.NewRegistry()
	id := reg.IDForBill("alice@in")
	a := &Admitter{Meter: reg}
	_, rel, err := a.AdmitConn(id, addr.Socksaddr{})
	if err != nil {
		t.Fatalf("放行: %v", err)
	}
	var live int64 = -1
	for _, s := range reg.Snapshot() {
		if s.Bill == "alice@in" {
			live = s.ConnsLive
		}
	}
	if live != 1 {
		t.Fatalf("登记后 connsLive 应为 1,实为 %d", live)
	}
	rel()
	for _, s := range reg.Snapshot() {
		if s.Bill == "alice@in" && s.ConnsLive != 0 {
			t.Fatalf("release 后 connsLive 应归零,实为 %d", s.ConnsLive)
		}
	}
}

// TestAdmitterNoLimits:既无闸也无计量 —— 零成本放行,meter 为 nil。
func TestAdmitterNoLimits(t *testing.T) {
	a := &Admitter{}
	m, rel, err := a.AdmitConn(cred.Ambient, addr.Socksaddr{})
	if err != nil || m != nil {
		t.Fatalf("无限额应放行且 meter=nil: m=%v err=%v", m, err)
	}
	rel()
}
