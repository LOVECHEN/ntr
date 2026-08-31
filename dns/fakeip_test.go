package dns

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/LOVECHEN/ntr/core/route"
)

func mkPool(t *testing.T, v4 string, v6 string, exclude ...string) *fakeIPPool {
	t.Helper()
	cfg := &FakeIPConfig{Inet4: netip.MustParsePrefix(v4), Exclude: exclude}
	if v6 != "" {
		cfg.Inet6 = netip.MustParsePrefix(v6)
	}
	return newFakeIPPool(cfg)
}

func TestFakeIPAllocStableAndReverse(t *testing.T) {
	p := mkPool(t, "198.18.0.0/15", "")
	ip1, ok := p.alloc("example.com.", dnsmessage.TypeA)
	if !ok {
		t.Fatal("alloc A failed")
	}
	if !p.p4.Contains(ip1) {
		t.Errorf("fake ip %v 不在段内", ip1)
	}
	// 同域名稳定复用
	ip2, _ := p.alloc("example.com", dnsmessage.TypeA)
	if ip1 != ip2 {
		t.Errorf("同域名两次分配不一致 %v != %v", ip1, ip2)
	}
	// 反查
	if d, ok := p.lookup(ip1); !ok || d != "example.com" {
		t.Errorf("lookup(%v)=%q,%v 期望 example.com", ip1, d, ok)
	}
	// 不同域名不同 IP
	ip3, _ := p.alloc("other.org", dnsmessage.TypeA)
	if ip3 == ip1 {
		t.Errorf("不同域名分配了同一 IP %v", ip3)
	}
}

func TestFakeIPExcludeAndNoV6(t *testing.T) {
	p := mkPool(t, "198.18.0.0/15", "", "lan", "direct.example")
	if !p.excluded("a.lan.") {
		t.Error("a.lan 应被排除")
	}
	if !p.excluded("direct.example") {
		t.Error("direct.example 应被排除")
	}
	if p.excluded("example.com") {
		t.Error("example.com 不应被排除")
	}
	// 无 v6 段:AAAA 分配失败
	if _, ok := p.alloc("x.com", dnsmessage.TypeAAAA); ok {
		t.Error("无 v6 段 AAAA 不该分配成功")
	}
	// 有 v6 段:AAAA 成功且落在 v6
	p6 := mkPool(t, "198.18.0.0/15", "fc00::/18")
	ip, ok := p6.alloc("x.com", dnsmessage.TypeAAAA)
	if !ok || !ip.Is6() || !p6.p6.Contains(ip) {
		t.Errorf("AAAA 分配 %v ok=%v 期望 v6 段内", ip, ok)
	}
}

func TestFakeIPRecycleFIFO(t *testing.T) {
	// 极小段 /30 → 可用地址极少,强制回收
	p := mkPool(t, "198.18.0.0/30", "")
	seen := map[netip.Addr]string{}
	var first netip.Addr
	for i, dom := range []string{"a.com", "b.com", "c.com", "d.com", "e.com"} {
		ip, ok := p.alloc(dom, dnsmessage.TypeA)
		if !ok {
			t.Fatalf("alloc %s 失败", dom)
		}
		if i == 0 {
			first = ip
		}
		seen[ip] = dom
	}
	// 环形回收后,最初的域名映射应已被驱逐(其 IP 现属新域名)
	if d, ok := p.lookup(first); ok && d == "a.com" {
		t.Errorf("回收后 first IP 仍指向 a.com,未驱逐")
	}
}

func TestResolverExchangeFakeIPRoundTrip(t *testing.T) {
	r, err := New([]Nameserver{{Tag: "up", Address: "udp://1.1.1.1:53", Detour: fakeUpstream{calls: new(atomic.Int64)}}},
		nil, "race", nil, &FakeIPConfig{Inet4: netip.MustParsePrefix("198.18.0.0/15")})
	if err != nil {
		t.Fatal(err)
	}
	// A 查询 example.com → 合成伪 IP,不触发上游
	q, _ := buildQuery("example.com", dnsmessage.TypeA)
	resp, err := r.Exchange(context.Background(), &route.Message{Raw: q})
	if err != nil {
		t.Fatal(err)
	}
	na, ok := parseAddrs(resp.Raw)
	if !ok || len(na) != 1 {
		t.Fatalf("期望 1 条 A 记录,得 %v ok=%v", na, ok)
	}
	fip := toNetip(na)[0]
	if !r.fake.p4.Contains(fip) {
		t.Errorf("合成的 %v 不在伪 IP 段", fip)
	}
	// 反查回域名
	if d, ok := r.FakeIPToDomain(fip); !ok || d != "example.com" {
		t.Errorf("FakeIPToDomain(%v)=%q,%v 期望 example.com", fip, d, ok)
	}
	// 非伪 IP 反查失败
	if _, ok := r.FakeIPToDomain(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("8.8.8.8 不该反查出域名")
	}
}
