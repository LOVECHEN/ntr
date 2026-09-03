package rule

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
)

// naiveRoute 是朴素 O(n) 首个命中匹配器(参照实现):自顶向下,首个命中的规则决定目标。
// property test 用它对拍 Engine —— 承设计 §8.3.3「须 property test 与朴素线性匹配器对拍、断言选中一致」。
func naiveRoute(rules []Rule, def string, dst addr.Socksaddr) string {
	for i := range rules {
		if ruleMatches(&rules[i], dst) {
			return rules[i].To
		}
	}
	return def
}

func ruleMatches(r *Rule, dst addr.Socksaddr) bool {
	if r.Op != "" { // 组合规则:递归求值(naive 参照,对拍 Engine 的 evaluator)
		var res bool
		if r.Op == "and" {
			res = true
			for i := range r.Sub {
				if !ruleMatches(&r.Sub[i], dst) {
					res = false
					break
				}
			}
		} else { // or
			for i := range r.Sub {
				if ruleMatches(&r.Sub[i], dst) {
					res = true
					break
				}
			}
		}
		if r.Not {
			res = !res
		}
		return res
	}
	if dst.IsFqdn() {
		host := normDomain(dst.Fqdn)
		for _, d := range r.Domain {
			if host == normDomain(d) {
				return true
			}
		}
		for _, s := range r.DomainSuffix {
			s = normDomain(strings.TrimPrefix(s, "."))
			if host == s || strings.HasSuffix(host, "."+s) {
				return true
			}
		}
		for _, k := range r.DomainKeyword {
			if strings.Contains(host, strings.ToLower(k)) {
				return true
			}
		}
	}
	if dst.IsIP() {
		for _, c := range r.IPCIDR {
			if p, err := netip.ParsePrefix(c); err == nil && p.Contains(dst.Addr.Unmap()) {
				return true
			}
		}
		for _, gs := range r.GeoIP {
			if gs.MatchIP(dst.Addr.Unmap()) {
				return true
			}
		}
	}
	for _, pt := range r.Port {
		if dst.Port == pt {
			return true
		}
	}
	return false
}

// TestEngineMatchesNaive 随机生成规则表 + 目标,断言 Engine.Route == naiveRoute(万次)。
func TestEngineMatchesNaive(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5eed1234))
	labels := []string{"google", "youtube", "cn", "example", "ads", "cdn", "net", "com", "org", "a", "b"}
	targets := []string{"direct", "proxy", "block", "hk", "jp"}
	genDomain := func() string {
		n := 1 + rng.Intn(3)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = labels[rng.Intn(len(labels))]
		}
		return strings.Join(parts, ".")
	}
	genCIDR := func() string {
		return fmt.Sprintf("%d.%d.0.0/%d", rng.Intn(256), rng.Intn(256), 8+rng.Intn(17))
	}
	// genLeaf 生成一个恰好一个维度的叶子规则(无 To,可作子规则)。
	genLeaf := func() Rule {
		r := Rule{}
		switch rng.Intn(5) {
		case 0:
			for k := 0; k < 1+rng.Intn(2); k++ {
				r.Domain = append(r.Domain, genDomain())
			}
		case 1:
			for k := 0; k < 1+rng.Intn(2); k++ {
				r.DomainSuffix = append(r.DomainSuffix, genDomain())
			}
		case 2:
			r.DomainKeyword = []string{labels[rng.Intn(len(labels))]}
		case 3:
			for k := 0; k < 1+rng.Intn(2); k++ {
				r.IPCIDR = append(r.IPCIDR, genCIDR())
			}
		case 4:
			r.Port = []uint16{uint16(rng.Intn(4)) * 100} // 0/100/200/300
		}
		return r
	}
	// genRule 生成顶层规则:2/3 叶子、1/3 组合(and/or,可 Not,子规则含 1/4 概率嵌套组合)。
	genRule := func() Rule {
		to := targets[rng.Intn(len(targets))]
		if rng.Intn(3) != 0 {
			r := genLeaf()
			r.To = to
			return r
		}
		r := Rule{To: to, Op: []string{"and", "or"}[rng.Intn(2)], Not: rng.Intn(2) == 0}
		for k := 0; k < 1+rng.Intn(3); k++ {
			if rng.Intn(4) == 0 { // 嵌套组合子规则
				sub := Rule{Op: []string{"and", "or"}[rng.Intn(2)], Not: rng.Intn(2) == 0}
				for m := 0; m < 1+rng.Intn(2); m++ {
					sub.Sub = append(sub.Sub, genLeaf())
				}
				r.Sub = append(r.Sub, sub)
			} else {
				r.Sub = append(r.Sub, genLeaf())
			}
		}
		return r
	}
	genDst := func() addr.Socksaddr {
		port := uint16(rng.Intn(4)) * 100
		if rng.Intn(2) == 0 {
			return addr.FromFqdn(genDomain(), port)
		}
		var b [4]byte
		b[0], b[1], b[2], b[3] = byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))
		return addr.FromIPPort(netip.AddrPortFrom(netip.AddrFrom4(b), port))
	}

	for iter := range 20000 {
		nRules := rng.Intn(12)
		rules := make([]Rule, nRules)
		for i := range rules {
			rules[i] = genRule()
		}
		def := targets[rng.Intn(len(targets))]
		eng, err := Compile(rules, def)
		if err != nil {
			t.Fatalf("iter %d Compile 失败: %v", iter, err)
		}
		dst := genDst()
		got := eng.Route(dst)
		want := naiveRoute(rules, def, dst)
		if got != want {
			t.Fatalf("iter %d 分流不一致: dst=%+v got=%q want=%q\nrules=%+v def=%q", iter, dst, got, want, rules, def)
		}
	}
}

// TestEngineMinOrdinalNotLongestPrefix 显式守 §8.3.3 的 CIDR 陷阱:重叠 CIDR 取 min ord,非最长前缀。
func TestEngineMinOrdinalNotLongestPrefix(t *testing.T) {
	rules := []Rule{
		{IPCIDR: []string{"10.0.0.0/8"}, To: "A"},  // ord 0(更宽)
		{IPCIDR: []string{"10.1.0.0/16"}, To: "B"}, // ord 1(更窄,最长前缀会误选它)
	}
	eng, err := Compile(rules, "def")
	if err != nil {
		t.Fatal(err)
	}
	dst := addr.FromIPPort(netip.MustParseAddrPort("10.1.0.1:443"))
	if got := eng.Route(dst); got != "A" {
		t.Fatalf("min-ordinal 陷阱: 10.1.0.1 应命中 ord 更小的 A(非最长前缀 B),实得 %q", got)
	}
}

// TestEngineSuffixLabelBoundary 守后缀按标签边界(google.com 不匹配 notgoogle.com)。
func TestEngineSuffixLabelBoundary(t *testing.T) {
	eng, err := Compile([]Rule{{DomainSuffix: []string{"google.com"}, To: "proxy"}}, "direct")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"www.google.com": "proxy",
		"google.com":     "proxy",
		"notgoogle.com":  "direct", // 非标签边界,不匹配
		"google.com.cn":  "direct", // google.com 不是它的后缀标签
	}
	for host, want := range cases {
		if got := eng.Route(addr.FromFqdn(host, 443)); got != want {
			t.Errorf("suffix %q: got %q want %q", host, got, want)
		}
	}
}

// fakeIPSet 是测试用 geoip 集合:匹配预置的 IP 集。
type fakeIPSet struct{ hit map[netip.Addr]bool }

func (f fakeIPSet) MatchIP(ip netip.Addr) bool { return f.hit[ip.Unmap()] }

// TestEngineGeoIP 验证 geoip 维:命中集合的 IP → 规则 To,否则 default;且 min-ordinal 与 cidr 共存。
func TestEngineGeoIP(t *testing.T) {
	cn := fakeIPSet{hit: map[netip.Addr]bool{
		netip.MustParseAddr("223.5.5.5"):       true,
		netip.MustParseAddr("114.114.114.114"): true,
	}}
	eng, err := Compile([]Rule{
		{IPCIDR: []string{"8.8.8.0/24"}, To: "cidr-out"}, // ord0:优先于 geoip(同为 IP 维,但 min-ord)
		{GeoIP: []IPSet{cn}, To: "cn-out"},               // ord1
	}, "direct")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ ip, want string }{
		{"223.5.5.5", "cn-out"}, // 命中 geoip
		{"114.114.114.114", "cn-out"},
		{"8.8.8.8", "cidr-out"}, // 命中 cidr(ord0 < geoip ord1),且 8.8.8.8 不在 cn 集
		{"1.1.1.1", "direct"},   // 都不命中 → 兜底
	}
	for _, c := range cases {
		dst := addr.FromIPPort(netip.MustParseAddrPort(c.ip + ":80"))
		if got := eng.Route(dst); got != c.want {
			t.Errorf("Route(%s)=%q 期望 %q", c.ip, got, c.want)
		}
	}
}

// fakeFinder 是测试用 ProcessFinder:恒返回预置的 name/path/ok(不碰 /proc)。
type fakeFinder struct {
	name, path string
	ok         bool
}

func (f fakeFinder) FindProcess(string, netip.AddrPort) (string, string, bool) {
	return f.name, f.path, f.ok
}

// TestRouteProcess 覆盖 process 规则:name/path 命中、不命中回 default、finder nil / ok=false 不命中、
// 与 min-ordinal 交互(靠前的 process 规则赢靠后的 domain 规则)。
func TestRouteProcess(t *testing.T) {
	dst := addr.FromFqdn("example.com", 443)
	src := netip.MustParseAddrPort("127.0.0.1:40000")

	// process-name 命中
	e, err := Compile([]Rule{{ProcessName: []string{"curl"}, To: "proxy"}}, "direct")
	if err != nil {
		t.Fatal(err)
	}
	if g := e.RouteConn(dst, src, "tcp", "", fakeFinder{"curl", "/usr/bin/curl", true}); g != "proxy" {
		t.Errorf("process-name 命中=%q 期望 proxy", g)
	}
	// 进程名不同 → default
	if g := e.RouteConn(dst, src, "tcp", "", fakeFinder{"wget", "/usr/bin/wget", true}); g != "direct" {
		t.Errorf("进程名不匹配=%q 期望 direct", g)
	}
	// finder=nil → process 规则不参与 → default
	if g := e.RouteConn(dst, src, "tcp", "", nil); g != "direct" {
		t.Errorf("finder nil=%q 期望 direct", g)
	}
	// finder ok=false(查不到进程)→ 不命中 → default
	if g := e.RouteConn(dst, src, "tcp", "", fakeFinder{"", "", false}); g != "direct" {
		t.Errorf("finder ok=false=%q 期望 direct", g)
	}

	// process-path 命中
	e2, _ := Compile([]Rule{{ProcessPath: []string{"/opt/app/bin/foo"}, To: "vpn"}}, "direct")
	if g := e2.RouteConn(dst, src, "tcp", "", fakeFinder{"foo", "/opt/app/bin/foo", true}); g != "vpn" {
		t.Errorf("process-path 命中=%q 期望 vpn", g)
	}

	// min-ordinal:process 规则(ord0)在前,应赢 domain 规则(ord1)
	e3, _ := Compile([]Rule{
		{ProcessName: []string{"curl"}, To: "byproc"},
		{Domain: []string{"example.com"}, To: "bydomain"},
	}, "direct")
	if g := e3.RouteConn(dst, src, "tcp", "", fakeFinder{"curl", "/usr/bin/curl", true}); g != "byproc" {
		t.Errorf("process 在前应赢=%q 期望 byproc", g)
	}
	// domain 规则(ord0)在前,进程也匹配(ord1)→ domain 赢
	e4, _ := Compile([]Rule{
		{Domain: []string{"example.com"}, To: "bydomain"},
		{ProcessName: []string{"curl"}, To: "byproc"},
	}, "direct")
	if g := e4.RouteConn(dst, src, "tcp", "", fakeFinder{"curl", "/usr/bin/curl", true}); g != "bydomain" {
		t.Errorf("domain 在前应赢=%q 期望 bydomain", g)
	}

	// HasProcess 正确反映
	if !e.HasProcess() || e4.HasProcess() != true {
		t.Error("HasProcess 应为 true")
	}
	eNoProc, _ := Compile([]Rule{{Domain: []string{"a.com"}, To: "x"}}, "direct")
	if eNoProc.HasProcess() {
		t.Error("无 process 规则 HasProcess 应 false")
	}
	// Route(纯 dst,无源)不受 process 规则影响
	if g := e.Route(dst); g != "direct" {
		t.Errorf("Route 纯 dst=%q 期望 direct(process 不参与)", g)
	}
}

// TestRouteLogical 覆盖 and/or/not 组合规则:各算子、嵌套、process 子规则、min-ordinal 交互、校验。
func TestRouteLogical(t *testing.T) {
	ff := fakeFinder{"curl", "/usr/bin/curl", true}
	g443 := addr.FromFqdn("www.google.com", 443)
	g80 := addr.FromFqdn("www.google.com", 80)
	other := addr.FromFqdn("example.org", 443)
	src := netip.MustParseAddrPort("127.0.0.1:40000")

	// AND:域名后缀 google.com 且 端口 443 → proxy
	eAnd, err := Compile([]Rule{{
		Op: "and", To: "proxy",
		Sub: []Rule{{DomainSuffix: []string{"google.com"}}, {Port: []uint16{443}}},
	}}, "direct")
	if err != nil {
		t.Fatal(err)
	}
	if g := eAnd.Route(g443); g != "proxy" {
		t.Errorf("AND 全命中=%q 期望 proxy", g)
	}
	if g := eAnd.Route(g80); g != "direct" {
		t.Errorf("AND 端口不符=%q 期望 direct", g)
	}
	if g := eAnd.Route(other); g != "direct" {
		t.Errorf("AND 域名不符=%q 期望 direct", g)
	}

	// OR:域名 a 或 b → x
	eOr, _ := Compile([]Rule{{
		Op: "or", To: "x",
		Sub: []Rule{{Domain: []string{"a.com"}}, {Domain: []string{"b.com"}}},
	}}, "direct")
	if g := eOr.Route(addr.FromFqdn("a.com", 1)); g != "x" {
		t.Errorf("OR a=%q 期望 x", g)
	}
	if g := eOr.Route(addr.FromFqdn("b.com", 1)); g != "x" {
		t.Errorf("OR b=%q 期望 x", g)
	}
	if g := eOr.Route(addr.FromFqdn("c.com", 1)); g != "direct" {
		t.Errorf("OR c=%q 期望 direct", g)
	}

	// NOT:非 cn 后缀 → proxy(NOT(or(domain-suffix cn)))
	eNot, _ := Compile([]Rule{{
		Op: "or", Not: true, To: "proxy",
		Sub: []Rule{{DomainSuffix: []string{"cn"}}},
	}}, "direct")
	if g := eNot.Route(addr.FromFqdn("baidu.cn", 1)); g != "direct" {
		t.Errorf("NOT cn 命中(是cn)=%q 期望 direct", g)
	}
	if g := eNot.Route(addr.FromFqdn("google.com", 1)); g != "proxy" {
		t.Errorf("NOT cn(非cn)=%q 期望 proxy", g)
	}

	// 嵌套:AND[ OR[domain a, domain b], NOT[port 22] ] → nested
	eNest, _ := Compile([]Rule{{
		Op: "and", To: "nested",
		Sub: []Rule{
			{Op: "or", Sub: []Rule{{Domain: []string{"a.com"}}, {Domain: []string{"b.com"}}}},
			{Op: "or", Not: true, Sub: []Rule{{Port: []uint16{22}}}},
		},
	}}, "direct")
	if g := eNest.Route(addr.FromFqdn("a.com", 443)); g != "nested" {
		t.Errorf("嵌套 a:443=%q 期望 nested", g)
	}
	if g := eNest.Route(addr.FromFqdn("a.com", 22)); g != "direct" {
		t.Errorf("嵌套 a:22(被NOT挡)=%q 期望 direct", g)
	}
	if g := eNest.Route(addr.FromFqdn("z.com", 443)); g != "direct" {
		t.Errorf("嵌套 z:443(OR不中)=%q 期望 direct", g)
	}

	// 组合里含 process 子规则:AND[ process-name curl, port 443 ] → viaproc
	eProc, _ := Compile([]Rule{{
		Op: "and", To: "viaproc",
		Sub: []Rule{{ProcessName: []string{"curl"}}, {Port: []uint16{443}}},
	}}, "direct")
	if g := eProc.RouteConn(g443, src, "tcp", "", ff); g != "viaproc" {
		t.Errorf("AND+process 命中=%q 期望 viaproc", g)
	}
	if g := eProc.RouteConn(g443, src, "tcp", "", fakeFinder{"wget", "/usr/bin/wget", true}); g != "direct" {
		t.Errorf("AND+process 进程不符=%q 期望 direct", g)
	}
	// 纯 dst Route(无 finder):process 子规则不命中 → AND 失败 → default
	if g := eProc.Route(g443); g != "direct" {
		t.Errorf("Route 无源 process 子规则应不命中=%q 期望 direct", g)
	}

	// min-ordinal:组合规则(ord0)赢后面的叶子(ord1)
	eMix, _ := Compile([]Rule{
		{Op: "and", To: "bycombo", Sub: []Rule{{DomainSuffix: []string{"google.com"}}, {Port: []uint16{443}}}},
		{DomainSuffix: []string{"google.com"}, To: "byleaf"},
	}, "direct")
	if g := eMix.Route(g443); g != "bycombo" {
		t.Errorf("组合在前应赢=%q 期望 bycombo", g)
	}
	// 叶子(ord0)在前赢组合(ord1)
	eMix2, _ := Compile([]Rule{
		{DomainSuffix: []string{"google.com"}, To: "byleaf"},
		{Op: "and", To: "bycombo", Sub: []Rule{{DomainSuffix: []string{"google.com"}}, {Port: []uint16{443}}}},
	}, "direct")
	if g := eMix2.Route(g443); g != "byleaf" {
		t.Errorf("叶子在前应赢=%q 期望 byleaf", g)
	}

	// 校验错误
	bad := []struct {
		name string
		r    Rule
	}{
		{"op非法", Rule{Op: "xor", To: "x", Sub: []Rule{{Domain: []string{"a"}}}}},
		{"sub空", Rule{Op: "and", To: "x"}},
		{"组合带叶子维度", Rule{Op: "and", To: "x", Port: []uint16{1}, Sub: []Rule{{Domain: []string{"a"}}}}},
		{"子规则带to", Rule{Op: "and", To: "x", Sub: []Rule{{Domain: []string{"a"}, To: "nope"}}}},
		{"子规则多维度", Rule{Op: "and", To: "x", Sub: []Rule{{Domain: []string{"a"}, Port: []uint16{1}}}}},
	}
	for _, tc := range bad {
		if _, err := Compile([]Rule{tc.r}, "direct"); err == nil {
			t.Errorf("校验 %q 应报错但没有", tc.name)
		}
	}
}
