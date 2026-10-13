package service

import (
	"context"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/meter"
)

type tunUserKey struct{}

// TestSessionTunnelAdmit:整包隧道一次接入 —— ctx 回读身份落到对应用户账上,记账回调累计、release 后冲刷并注销;
// 用户被停用时拒新隧道并关 closer。
func TestSessionTunnelAdmit(t *testing.T) {
	reg := meter.NewRegistry()
	id := reg.IDForBill("alice")
	readUser := func(ctx context.Context) (string, bool) {
		s, ok := ctx.Value(tunUserKey{}).(string)
		return s, ok
	}
	admit := SessionTunnelAdmit(&Admitter{Meter: reg}, map[string]cred.ID{"alice@cip": id}, readUser)
	ctx := context.WithValue(context.Background(), tunUserKey{}, "alice@cip")
	src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 4433}

	up, down, release, ok := admit(ctx, src, &closeSpy{})
	if !ok || up == nil || down == nil || release == nil {
		t.Fatalf("应放行且给记账回调: ok=%v up=%v down=%v", ok, up != nil, down != nil)
	}
	up(1200)
	down(3400)
	release()

	st := statOf(t, reg, id)
	if st.ConnsTotal != 1 || st.ConnsLive != 0 || st.Up != 1200 || st.Down != 3400 {
		t.Fatalf("隧道未按用户记账: %+v", st)
	}

	reg.Disable(id)
	spy := &closeSpy{}
	if _, _, _, ok := admit(ctx, src, spy); ok || !spy.closed {
		t.Fatalf("停用后应拒新隧道并关 closer: ok=%v closed=%v", ok, spy.closed)
	}
}

func statOf(t *testing.T, reg *meter.Registry, id cred.ID) meter.UserStat {
	t.Helper()
	for _, st := range reg.Snapshot() {
		if cred.ID(st.ID) == id {
			return st
		}
	}
	t.Fatal("计量表里没有该用户")
	return meter.UserStat{}
}
