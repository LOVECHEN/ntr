package dns

import (
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

// hostsMap 是静态 host→IP 映射:命中即就地合成权威应答、不走上游(也防这些域名的 DNS 泄漏)。
// 键 = 规范化域名(小写 + 末尾点,与 parseQuery 出的 qkey.name 同格式)。
type hostsMap struct {
	m map[string][]netip.Addr
}

// newHosts 从配置构造;空则返回 nil(Exchange 里 nil 检查后零开销跳过)。
func newHosts(in map[string][]netip.Addr) *hostsMap {
	if len(in) == 0 {
		return nil
	}
	h := &hostsMap{m: make(map[string][]netip.Addr, len(in))}
	for name, addrs := range in {
		h.m[dnsName(name)] = addrs
	}
	return h
}

// lookup 报告 name 是否有 hosts 条目;有则返回匹配 qtype(A→IPv4、AAAA→IPv6)的地址子集。
// ★有条目但无匹配 qtype 时仍 ok=true(返回空 = NODATA 权威应答),避免这些域名落到上游泄漏。
func (h *hostsMap) lookup(name string, qtype dnsmessage.Type) ([]netip.Addr, bool) {
	if h == nil {
		return nil, false
	}
	addrs, ok := h.m[name]
	if !ok {
		return nil, false
	}
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return nil, true // 非 A/AAAA(如 MX)但域名被 hosts 接管 → 空权威应答,不外泄
	}
	var out []netip.Addr
	for _, a := range addrs {
		switch {
		case qtype == dnsmessage.TypeA && a.Is4():
			out = append(out, a)
		case qtype == dnsmessage.TypeAAAA && a.Is6() && !a.Is4In6():
			out = append(out, a)
		}
	}
	return out, true
}

// buildHostsResponse 合成一份权威 A/AAAA 应答(TTL 600)。addrs 为空 → NODATA(仅问题段,无答案)。
func buildHostsResponse(id uint16, name string, qtype dnsmessage.Type, addrs []netip.Addr) []byte {
	dn, err := dnsmessage.NewName(name)
	if err != nil {
		return nil
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, RecursionAvailable: true, Authoritative: true},
		Questions: []dnsmessage.Question{{Name: dn, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	for _, a := range addrs {
		rh := dnsmessage.ResourceHeader{Name: dn, Type: qtype, Class: dnsmessage.ClassINET, TTL: 600}
		switch {
		case qtype == dnsmessage.TypeA && a.Is4():
			msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: rh, Body: &dnsmessage.AResource{A: a.As4()}})
		case qtype == dnsmessage.TypeAAAA && a.Is6():
			msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: rh, Body: &dnsmessage.AAAAResource{AAAA: a.As16()}})
		}
	}
	raw, err := msg.Pack()
	if err != nil {
		return nil
	}
	return raw
}
