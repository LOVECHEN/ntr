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
	genRule := func() Rule {
		r := Rule{To: targets[rng.Intn(len(targets))]}
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
