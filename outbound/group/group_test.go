package group

import (
	"context"
	"errors"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/link"
)

// markOut 是记名假出站:DialStream 返回一个内容为自己名字的 error,便于断言「选中了谁」。
type markOut struct{ name string }

func (m markOut) DialStream(context.Context, addr.Socksaddr) (link.Stream, error) {
	return nil, errors.New(m.name)
}
func (m markOut) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, errors.New(m.name)
}

func picked(t *testing.T, g *Group) string {
	t.Helper()
	_, err := g.DialStream(context.Background(), addr.FromFqdn("x.test", 80))
	if err == nil {
		t.Fatal("markOut 应返回带名字的 error")
	}
	return err.Error()
}

func mems(names ...string) []Member {
	var ms []Member
	for _, n := range names {
		ms = append(ms, Member{Name: n, Out: markOut{n}})
	}
	return ms
}

func TestGroupSelectAndManualSwitch(t *testing.T) {
	g, err := New(Options{Name: "g", Strategy: Select, Default: "b", Members: mems("a", "b", "c")})
	if err != nil {
		t.Fatal(err)
	}
	if got := picked(t, g); got != "b" {
		t.Fatalf("select 默认应选 b,得 %q", got)
	}
	if !g.SelectOutbound("c") {
		t.Fatal("SelectOutbound(c) 应成功")
	}
	if got := picked(t, g); got != "c" {
		t.Fatalf("手选后应选 c,得 %q", got)
	}
	if g.SelectOutbound("nope") {
		t.Fatal("选不存在成员应失败")
	}
	if g.NeedsHealth() {
		t.Fatal("select 组不需健康探测")
	}
}

func TestGroupLoadBalanceRoundRobin(t *testing.T) {
	g, _ := New(Options{Name: "g", Strategy: LoadBalance, Members: mems("a", "b", "c")})
	seen := map[string]bool{}
	for i := 0; i < 9; i++ {
		seen[picked(t, g)] = true
	}
	if len(seen) != 3 {
		t.Fatalf("轮询应命中全部 3 成员,实得 %d 个:%v", len(seen), seen)
	}
}

func TestGroupLoadBalanceConsistentHash(t *testing.T) {
	g, _ := New(Options{Name: "g", Strategy: LoadBalance, LBHash: true, Members: mems("a", "b", "c")})
	first := picked(t, g) // 同一 dst(x.test:80)恒同成员
	for i := 0; i < 8; i++ {
		if got := picked(t, g); got != first {
			t.Fatalf("一致性哈希同 dst 应恒选 %q,却得 %q", first, got)
		}
	}
}

func TestGroupNoMembers(t *testing.T) {
	if _, err := New(Options{Name: "g", Strategy: Select}); err == nil {
		t.Fatal("无成员应报错")
	}
}
