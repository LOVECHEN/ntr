package dns

import (
	"fmt"
	"strings"
)

// NameserverPolicy 是「按域名选上游」策略(承设计 §10.1 policy;config 期传入,对齐 mihomo
// nameserver-policy / sing-box domain-based DNS server 选择)。查询域名命中(任一域名维度匹配)
// 时,只用 Nameservers 指定的上游 tag 子集,而非默认全表 —— 让不同域名走不同 DNS 上游。
type NameserverPolicy struct {
	Domain        []string // 精确域名(bare,大小写不敏感)
	DomainSuffix  []string // 域名后缀(标签边界:a.example.com ∈ suffix example.com)
	DomainKeyword []string // 域名子串
	Nameservers   []string // 命中时用的上游 tag(引用 Nameserver.Tag;≥1)
}

// domainMatcher 是纯字符串域名判定(dns 自包含,不依赖 rule/geo)。规则全存 bare 小写。
type domainMatcher struct {
	exact   map[string]struct{}
	suffix  []string
	keyword []string
}

func newDomainMatcher(domain, suffix, keyword []string) *domainMatcher {
	m := &domainMatcher{exact: make(map[string]struct{}, len(domain))}
	for _, d := range domain {
		m.exact[bareLower(d)] = struct{}{}
	}
	for _, s := range suffix {
		m.suffix = append(m.suffix, bareLower(s))
	}
	for _, k := range keyword {
		m.keyword = append(m.keyword, strings.ToLower(k))
	}
	return m
}

// match 判定 name(可带尾点/任意大小写)是否命中。后缀按标签边界匹配(不误命中 notexample.com)。
func (m *domainMatcher) match(name string) bool {
	n := bareLower(name)
	if _, ok := m.exact[n]; ok {
		return true
	}
	for _, s := range m.suffix {
		if n == s || (len(n) > len(s) && strings.HasSuffix(n, s) && n[len(n)-len(s)-1] == '.') {
			return true
		}
	}
	for _, k := range m.keyword {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// bareLower 去尾点 + 小写(DNS 域名规范化,对齐 parseQuery 的 name 形态)。
func bareLower(s string) string {
	s = strings.ToLower(s)
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}

// buildPolicies 把 config 期 NameserverPolicy 解析成运行时 policyRule:校验每条至少一个域名维度、
// 至少一个上游,且引用的 tag 均已在 nameservers 定义(编译期挡悬空,守「绝不静默」)。
func buildPolicies(policies []NameserverPolicy, byTag map[string]*upstream) ([]policyRule, error) {
	if len(policies) == 0 {
		return nil, nil
	}
	prs := make([]policyRule, 0, len(policies))
	for i, pol := range policies {
		if len(pol.Domain)+len(pol.DomainSuffix)+len(pol.DomainKeyword) == 0 {
			return nil, fmt.Errorf("dns: nameserver-policy[%d] 无域名匹配维度(domain/domain-suffix/domain-keyword)", i)
		}
		if len(pol.Nameservers) == 0 {
			return nil, fmt.Errorf("dns: nameserver-policy[%d] 未指定命中用的上游 nameserver", i)
		}
		ups := make([]*upstream, 0, len(pol.Nameservers))
		for _, tag := range pol.Nameservers {
			u, ok := byTag[tag]
			if !ok {
				return nil, fmt.Errorf("dns: nameserver-policy[%d] 引用未定义上游 tag %q", i, tag)
			}
			ups = append(ups, u)
		}
		prs = append(prs, policyRule{m: newDomainMatcher(pol.Domain, pol.DomainSuffix, pol.DomainKeyword), ups: ups})
	}
	return prs, nil
}

// upstreamsFor 返回查 name 该用的上游:第一条命中的 policy 的子集,无命中则默认全表。
func (p *plan) upstreamsFor(name string) []*upstream {
	if name != "" {
		for i := range p.policies {
			if p.policies[i].m.match(name) {
				return p.policies[i].ups
			}
		}
	}
	return p.nameservers
}
