package meter

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// TestMemGuardPhases:注入采样器,验证 tick 按 RSS 落档 normal/soft/hard,AdmitOK 在 soft/hard 拒新并计数。
func TestMemGuardPhases(t *testing.T) {
	var cur atomic.Uint64
	g := NewMemGuard(nil, 1000, 800, 920, time.Hour, 8)
	g.sample = func() uint64 { return cur.Load() }

	cur.Store(500)
	g.tick()
	if MemPhase(g.phase.Load()) != MemNormal {
		t.Fatalf("500<800 应 normal,实为 %v", MemPhase(g.phase.Load()))
	}
	if !g.AdmitOK() {
		t.Fatal("normal 档应放行")
	}

	cur.Store(850)
	g.tick()
	if MemPhase(g.phase.Load()) != MemSoft {
		t.Fatalf("850≥800 应 soft")
	}
	if g.AdmitOK() {
		t.Fatal("soft 档应拒新")
	}
	if g.Stat().SoftRejected != 1 {
		t.Fatalf("soft 拒新应计 1,实为 %d", g.Stat().SoftRejected)
	}

	cur.Store(950)
	g.tick()
	if MemPhase(g.phase.Load()) != MemHard {
		t.Fatalf("950≥920 应 hard")
	}
	if g.AdmitOK() { // hard 也拒新
		t.Fatal("hard 档应拒新")
	}

	cur.Store(400)
	g.tick()
	if MemPhase(g.phase.Load()) != MemNormal {
		t.Fatalf("回落 400 应 normal")
	}
}

// TestMemGuardNilAdmit:nil 守卫恒放行(零成本路径)。
func TestMemGuardNilAdmit(t *testing.T) {
	var g *MemGuard
	if !g.AdmitOK() {
		t.Fatal("nil MemGuard.AdmitOK 应恒真")
	}
}

// TestMemGuardHardEvictsMostIdle:hard 档踢「最久无数据传输」的连接。登记 3 条设不同 lastActive,
// tick 到 hard → evictIdle(1) 应踢掉最久空闲那条(且只踢它)。
func TestMemGuardHardEvictsMostIdle(t *testing.T) {
	reg := NewRegistry()
	id := reg.IDForBill("u@in")
	src := netip.MustParseAddr("10.0.0.9")

	var killedA, killedB, killedC atomic.Bool
	openWith := func(flag *atomic.Bool) uint64 {
		_, _, ok := reg.Open(id, src, func() { flag.Store(true) })
		if !ok {
			t.Fatal("Open 应放行")
		}
		// 返回该连接的 connID(connSeq 单调,最近一个)
		return reg.connSeq.Load()
	}
	cidA := openWith(&killedA) // 最先开
	cidB := openWith(&killedB)
	cidC := openWith(&killedC)

	// 直接改 lastActive:A 最久空闲(最小),C 最新。
	c := reg.cell(id)
	c.liveMu.Lock()
	c.live[cidA].lastActive.Store(100)
	c.live[cidB].lastActive.Store(200)
	c.live[cidC].lastActive.Store(300)
	c.liveMu.Unlock()

	g := NewMemGuard(reg, 1000, 800, 900, time.Hour, 1) // evictBatch=1:一次只踢一条
	g.sample = func() uint64 { return 950 }             // ≥hard
	g.tick()

	// 等异步 kill 落地
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if killedA.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !killedA.Load() {
		t.Fatal("应踢掉最久空闲的 A")
	}
	if killedB.Load() || killedC.Load() {
		t.Fatal("evictBatch=1 只应踢 A,B/C 不该被踢")
	}
	if g.Stat().HardEvicted != 1 {
		t.Fatalf("hardEvicted 应为 1,实为 %d", g.Stat().HardEvicted)
	}
	// A 已从 live 摘除,B/C 仍在
	c.liveMu.Lock()
	_, aStill := c.live[cidA]
	_, bStill := c.live[cidB]
	c.liveMu.Unlock()
	if aStill {
		t.Fatal("A 应已从 live 摘除")
	}
	if !bStill {
		t.Fatal("B 应仍在 live")
	}
}

// TestCurrentMemBytesNonZero:采样器应返回非零(Linux 走 RSS,其它平台走 runtime)。
func TestCurrentMemBytesNonZero(t *testing.T) {
	if currentMemBytes() == 0 {
		t.Fatal("currentMemBytes 不应为 0")
	}
}

// TestHuman:字节格式化 sanity。
func TestHuman(t *testing.T) {
	cases := map[uint64]string{512: "512B", 1024: "1.0KiB", 1610612736: "1.5GiB"}
	for in, want := range cases {
		if got := human(in); got != want {
			t.Errorf("human(%d)=%q 期望 %q", in, got, want)
		}
	}
}
