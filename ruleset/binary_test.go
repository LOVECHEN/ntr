package ruleset

// 二进制规则集(mihomo .mrs / sing-box .srs)读取的离线单测:内嵌由 mihomo/sing-box 亲自编出的
// 极小真文件(base64),断言 NTR reader 的匹配结果 == 各家自身语义。规模级的字节对拍(648 探针 0 失配)
// 在 docs/interop-scripts/ix-{mrs,srs}.sh(CI 里跑,拉真镜像现编现验)。

import (
	"encoding/base64"
	"net/netip"
	"testing"
)

// mihomo convert-ruleset domain text {example.com}
const b64DomMRS = "KLUv/QQANQEAZAFNUlMBAAhqqqoAC21vYy5lbHBtYXhlBQBgmJ3yaLrBMgGu0wIITaSF"

// mihomo convert-ruleset ipcidr text {223.5.5.0/24}
const b64IPMRS = "KLUv/QQANQEAdAFNUlMBAQAAAAD//98FBQAAAP//3wUF/wUAQxEGJFgKrBDA4Iq6kc8O"

// sing-box rule-set compile {domain_suffix: example.com}
const b64DomSRS = "U1JTAXjaYmRgYmBkAAMNCINt1apVvLn5yXqpOQW5iRWperz/GQABAAD//1gDB9I="

// sing-box rule-set compile {ip_cidr: 223.5.5.0/24}
const b64IPSRS = "U1JTAXjaYmRgY2SAAEaW+6ysDCDi/38GQAAAAP//FXgD4g=="

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMRSDomain(t *testing.T) {
	ds, err := ParseMRSDomain(mustB64(t, b64DomMRS))
	if err != nil {
		t.Fatal(err)
	}
	// mihomo 裸 example.com = 精确
	for host, want := range map[string]bool{
		"example.com": true, "www.example.com": false, "example.org": false,
	} {
		if got := ds.MatchDomain(host); got != want {
			t.Errorf("MRS domain %q: got %v want %v", host, got, want)
		}
	}
	// behavior 不符应报错
	if _, err := ParseMRSIP(mustB64(t, b64DomMRS)); err == nil {
		t.Error("domain .mrs 当 ip 解析应报 behavior 错")
	}
}

func TestMRSIP(t *testing.T) {
	is, err := ParseMRSIP(mustB64(t, b64IPMRS))
	if err != nil {
		t.Fatal(err)
	}
	for s, want := range map[string]bool{
		"223.5.5.5": true, "223.5.5.255": true, "223.5.6.1": false, "1.1.1.1": false,
	} {
		if got := is.MatchIP(netip.MustParseAddr(s)); got != want {
			t.Errorf("MRS ip %q: got %v want %v", s, got, want)
		}
	}
}

func TestSRSDomain(t *testing.T) {
	ds, err := ParseSRSDomain(mustB64(t, b64DomSRS))
	if err != nil {
		t.Fatal(err)
	}
	// sing domain_suffix example.com = apex + 子域
	for host, want := range map[string]bool{
		"example.com": true, "www.example.com": true, "a.b.example.com": true,
		"notexample.com": false, "example.org": false,
	} {
		if got := ds.MatchDomain(host); got != want {
			t.Errorf("SRS domain %q: got %v want %v", host, got, want)
		}
	}
}

func TestSRSIP(t *testing.T) {
	is, err := ParseSRSIP(mustB64(t, b64IPSRS))
	if err != nil {
		t.Fatal(err)
	}
	for s, want := range map[string]bool{
		"223.5.5.5": true, "223.5.5.0": true, "223.5.6.1": false, "8.8.8.8": false,
	} {
		if got := is.MatchIP(netip.MustParseAddr(s)); got != want {
			t.Errorf("SRS ip %q: got %v want %v", s, got, want)
		}
	}
}

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		b    []byte
		want int
	}{
		{mustB64(t, b64DomMRS), fmtMRS},
		{mustB64(t, b64DomSRS), fmtSRS},
		{[]byte("DOMAIN,example.com,PROXY\n"), fmtText},
		{[]byte(".google.com\n"), fmtText},
	}
	for i, c := range cases {
		if got := detectFormat(c.b); got != c.want {
			t.Errorf("case %d: detectFormat=%d want %d", i, got, c.want)
		}
	}
}
