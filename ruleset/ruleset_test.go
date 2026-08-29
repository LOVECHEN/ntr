package ruleset

import (
	"net/netip"
	"testing"
)

func TestParseDomainList(t *testing.T) {
	ds := ParseDomainList([]byte(".apple.com\ngoogle.com\nfull:exact.test\nkeyword:ads\n# comment\n\n+.qq.com\n"))
	cases := map[string]bool{
		"www.apple.com":  true, // .apple.com 后缀
		"apple.com":      true,
		"notapple.com":   false, // 非标签边界
		"www.google.com": true,  // 裸域名按后缀
		"exact.test":     true,  // full 精确
		"sub.exact.test": false, // full 不含子域
		"ads.example":    true,  // keyword
		"im.qq.com":      true,  // +. 后缀
	}
	for host, want := range cases {
		if got := ds.MatchDomain(host); got != want {
			t.Errorf("MatchDomain(%q)=%v 期望 %v", host, got, want)
		}
	}
}

func TestParseIPList(t *testing.T) {
	is := ParseIPList([]byte("1.2.3.0/24\n8.8.8.8\n# c\n2001:db8::/32\n"))
	cases := map[string]bool{
		"1.2.3.5":     true,
		"1.2.4.5":     false,
		"8.8.8.8":     true,
		"8.8.8.9":     false,
		"2001:db8::1": true,
	}
	for s, want := range cases {
		if got := is.MatchIP(netip.MustParseAddr(s)); got != want {
			t.Errorf("MatchIP(%q)=%v 期望 %v", s, got, want)
		}
	}
}

func TestParseClassical(t *testing.T) {
	ds := ParseClassical([]byte("DOMAIN,exact.com\nDOMAIN-SUFFIX,cdn.net\nDOMAIN-KEYWORD,track\nIP-CIDR,1.2.3.0/24,no-resolve\n"))
	if !ds.MatchDomain("exact.com") || !ds.MatchDomain("a.cdn.net") || !ds.MatchDomain("x.track.y") {
		t.Fatal("classical 域名匹配不对")
	}
	if ds.MatchDomain("other.com") {
		t.Fatal("classical 不该匹配 other.com")
	}
}
