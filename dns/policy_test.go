package dns

import (
	"sync/atomic"
	"testing"
)

func TestDomainMatcher(t *testing.T) {
	m := newDomainMatcher(
		[]string{"exact.com"},
		[]string{"suffix.net"},
		[]string{"keyw"},
	)
	cases := []struct {
		name string
		want bool
	}{
		{"exact.com.", true},          // 精确(带尾点)
		{"EXACT.COM", true},           // 大小写不敏感
		{"x.exact.com", false},        // 精确不匹配子域
		{"suffix.net", true},          // 后缀 == 自身
		{"a.suffix.net.", true},       // 后缀标签边界
		{"notsuffix.net", false},      // 后缀非标签边界(not+suffix 不算)
		{"has-keyw-inside.org", true}, // 子串
		{"unrelated.io", false},
	}
	for _, c := range cases {
		if got := m.match(c.name); got != c.want {
			t.Errorf("match(%q)=%v 期望 %v", c.name, got, c.want)
		}
	}
}

func TestUpstreamsForPolicy(t *testing.T) {
	nss := []Nameserver{
		{Tag: "A", Address: "udp://10.0.0.1:53", Detour: fakeUpstream{calls: new(atomic.Int64)}},
		{Tag: "B", Address: "udp://10.0.0.2:53", Detour: fakeUpstream{calls: new(atomic.Int64)}},
	}
	pol := []NameserverPolicy{{DomainSuffix: []string{"policy.test"}, Nameservers: []string{"B"}}}
	pl, err := buildPlan(nss, pol, "sequential", nil)
	if err != nil {
		t.Fatal(err)
	}
	// 命中 policy → 只有 B。
	if ups := pl.upstreamsFor("foo.policy.test."); len(ups) != 1 || ups[0].tag != "B" {
		t.Fatalf("policy.test 应选 [B],得 %v", tags(ups))
	}
	// 未命中 → 默认全表 [A,B]。
	if ups := pl.upstreamsFor("bar.other.com."); len(ups) != 2 {
		t.Fatalf("other 应用默认全表 [A,B],得 %v", tags(ups))
	}
	// 空 name(无法解析的查询)→ 默认全表。
	if ups := pl.upstreamsFor(""); len(ups) != 2 {
		t.Fatalf("空 name 应用默认全表,得 %v", tags(ups))
	}
}

func TestBuildPoliciesErrors(t *testing.T) {
	nss := []Nameserver{{Tag: "A", Address: "udp://10.0.0.1:53", Detour: fakeUpstream{calls: new(atomic.Int64)}}}
	bad := []struct {
		name string
		pol  NameserverPolicy
	}{
		{"引用未定义 tag", NameserverPolicy{DomainSuffix: []string{"x.com"}, Nameservers: []string{"ZZZ"}}},
		{"无域名维度", NameserverPolicy{Nameservers: []string{"A"}}},
		{"无上游", NameserverPolicy{DomainSuffix: []string{"x.com"}}},
	}
	for _, c := range bad {
		if _, err := buildPlan(nss, []NameserverPolicy{c.pol}, "race", nil); err == nil {
			t.Errorf("%s:应报错但通过了", c.name)
		}
	}
}

func tags(ups []*upstream) []string {
	out := make([]string, 0, len(ups))
	for _, u := range ups {
		out = append(out, u.tag)
	}
	return out
}
