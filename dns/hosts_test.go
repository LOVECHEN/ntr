package dns

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestHostsLookupAndResponse(t *testing.T) {
	h := newHosts(map[string][]netip.Addr{
		"pinned.test": {netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("2001:db8::1")},
	})
	// A 命中(键规范化成 pinned.test.,与 parseQuery 的 qkey.name 同格式)
	a, ok := h.lookup("pinned.test.", dnsmessage.TypeA)
	if !ok || len(a) != 1 || a[0] != netip.MustParseAddr("9.9.9.9") {
		t.Fatalf("A 命中不对: ok=%v addrs=%v", ok, a)
	}
	// AAAA 命中
	if a6, ok := h.lookup("pinned.test.", dnsmessage.TypeAAAA); !ok || len(a6) != 1 || a6[0] != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("AAAA 命中不对: ok=%v addrs=%v", ok, a6)
	}
	// 未配的域名 → miss(应落上游)
	if _, ok := h.lookup("other.test.", dnsmessage.TypeA); ok {
		t.Fatal("未配域名应 miss")
	}
	// 有条目但问 MX → ok=true 但空(NODATA 权威应答,不外泄)
	if mx, ok := h.lookup("pinned.test.", dnsmessage.TypeMX); !ok || len(mx) != 0 {
		t.Fatalf("hosts 接管域名的非 A/AAAA 应 NODATA: ok=%v n=%d", ok, len(mx))
	}
	// 合成应答可解回 9.9.9.9
	raw := buildHostsResponse(0x1234, "pinned.test.", dnsmessage.TypeA, a)
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		t.Fatalf("应答解包失败: %v", err)
	}
	if m.Header.ID != 0x1234 || !m.Header.Response || len(m.Answers) != 1 {
		t.Fatalf("应答头/答案数不对: %+v", m.Header)
	}
	if ar, ok := m.Answers[0].Body.(*dnsmessage.AResource); !ok || netip.AddrFrom4(ar.A) != netip.MustParseAddr("9.9.9.9") {
		t.Fatalf("应答 A 记录不是 9.9.9.9")
	}
	// 空 hosts → nil(零开销)
	if newHosts(nil) != nil {
		t.Fatal("空 hosts 应返回 nil")
	}
}
