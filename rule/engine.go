// Package rule 实现承设计 §8.3 的分流规则引擎:有序规则表、自顶向下、【首个命中】生效,
// 末尾 default 兜底。核心技法 min-ordinal(§8.3.3):每条规则恰好一个维度谓词,ord=声明序;
// 「首个命中 = min{i: 规则 i 命中}」。对每个维度预建索引返回「命中该维度的最小 ord」,全局答案
// = 各维度 min 的 min —— 精确还原 Clash/mihomo 式首个命中,而无需逐条线性扫。
//
// ★correctness 陷阱(§8.3.3,由 engine_test.go 的 property test 对拍朴素 O(n) 匹配器守):
// 后缀 / CIDR 取「查询路径上【所有】命中前缀/后缀的 min ord」,【不是 longest-prefix】。
// 例 `ip-cidr 10/8→A`(ord0) 后 `ip-cidr 10.1/16→B`(ord1),对 10.1.0.1 首个命中是 A(ord 更小),
// 非最长前缀 B。故 CIDR 沿查询【收集全部包含前缀取 min】,后缀沿标签父链取 min。
//
// 维度(v1):domain(exact/suffix/keyword)、ip-cidr、port。network/cred/geoip/geosite/rule-set/
// and-or-not 逻辑残余为后续增量(承 §8.3.2 全集),同一 min-ordinal 骨架上叠加。
// 本包只 import addr(核心类型),不碰 proto/transport,合插件门禁。
package rule

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/LOVECHEN/ntr/addr"
)

// ordNone 是「无命中」哨兵(大于任何合法 ord)。
const ordNone = ^uint32(0)

// IPSet 是「IP 集合成员判定」谓词(geoip 的抽象;实现在 geo 包,rule 只认接口、不碰 mmdb I/O)。
type IPSet interface {
	MatchIP(ip netip.Addr) bool
}

// DomainSet 是「域名集合成员判定」谓词(geosite/rule-set domain 的抽象;实现在 geo/ruleset,rule 只认接口)。
type DomainSet interface {
	MatchDomain(host string) bool // host 已规范化(小写、无末尾点)
}

// Rule 是一条规则:恰好【一个】维度谓词非空 + 目标 To(出站/链名)。ord 由 Compile 按声明序赋。
type Rule struct {
	Domain        []string    // 精确域名(exact)
	DomainSuffix  []string    // 域名后缀(按标签边界)
	DomainKeyword []string    // 域名子串
	IPCIDR        []string    // CIDR 前缀(仅对 IP 目标)
	Port          []uint16    // 目标端口
	GeoIP         []IPSet     // geoip 国码集合(仅对 IP 目标;由 config 从 mmdb 建好传入)
	GeoSite       []DomainSet // geosite 域名集合(仅对域名目标;由 config 从 geosite.dat 建好传入)
	To            string      // 命中后派发到的出站/链名
}

// dimCount 返回本规则设了几个维度(须恰好 1)。
func (r *Rule) dimCount() int {
	n := 0
	for _, nonEmpty := range []bool{
		len(r.Domain) > 0, len(r.DomainSuffix) > 0, len(r.DomainKeyword) > 0,
		len(r.IPCIDR) > 0, len(r.Port) > 0, len(r.GeoIP) > 0, len(r.GeoSite) > 0,
	} {
		if nonEmpty {
			n++
		}
	}
	return n
}

type cidrEntry struct {
	p   netip.Prefix
	ord uint32
}
type kwEntry struct {
	kw  string
	ord uint32
}
type geoEntry struct {
	set IPSet
	ord uint32
}
type siteEntry struct {
	set DomainSet
	ord uint32
}

// Engine 是编译后的规则引擎:各维度索引 + default。只读、并发安全(编译后不改)。
type Engine struct {
	targets []string          // ord -> 目标名
	def     string            // 未命中兜底
	exact   map[string]uint32 // 精确域名 -> min ord
	suffix  map[string]uint32 // 后缀标签串 -> min ord
	keyword []kwEntry         // 子串,逐个点查(逻辑上是残余,但常用故单列)
	cidr    []cidrEntry       // CIDR,逐个点查取 min(路径全收集,非最长前缀)
	geoip   []geoEntry        // geoip 集合,逐个 MatchIP 取 min(仅 IP 目标)
	geosite []siteEntry       // geosite 集合,逐个 MatchDomain 取 min(仅域名目标)
	ports   map[uint16]uint32 // 端口 -> min ord
}

// Compile 把有序规则表 + default 编成 Engine。纯函数、无 I/O(承 §4.6 Compile 阶段)。
// 校验:每条规则恰好一个维度;CIDR 可解析;default 非空。
func Compile(rules []Rule, def string) (*Engine, error) {
	if def == "" {
		return nil, fmt.Errorf("rule: routing.default 不可为空(未命中兜底出站)")
	}
	e := &Engine{
		def:     def,
		targets: make([]string, len(rules)),
		exact:   map[string]uint32{},
		suffix:  map[string]uint32{},
		ports:   map[uint16]uint32{},
	}
	for i := range rules {
		r := &rules[i]
		if r.To == "" {
			return nil, fmt.Errorf("rule[%d]: 缺 to(目标出站)", i)
		}
		if n := r.dimCount(); n != 1 {
			return nil, fmt.Errorf("rule[%d]: 须恰好一个维度谓词,实为 %d(v1 尚不支持 and/or/not 组合)", i, n)
		}
		ord := uint32(i)
		e.targets[i] = r.To
		for _, d := range r.Domain {
			putMin(e.exact, normDomain(d), ord)
		}
		for _, s := range r.DomainSuffix {
			putMin(e.suffix, normDomain(strings.TrimPrefix(s, ".")), ord)
		}
		for _, k := range r.DomainKeyword {
			e.keyword = append(e.keyword, kwEntry{strings.ToLower(k), ord})
		}
		for _, c := range r.IPCIDR {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("rule[%d]: ip-cidr %q 解析失败:%w", i, c, err)
			}
			e.cidr = append(e.cidr, cidrEntry{p.Masked(), ord})
		}
		for _, pt := range r.Port {
			putMin(e.ports, pt, ord)
		}
		for _, gs := range r.GeoIP {
			e.geoip = append(e.geoip, geoEntry{gs, ord})
		}
		for _, ds := range r.GeoSite {
			e.geosite = append(e.geosite, siteEntry{ds, ord})
		}
	}
	return e, nil
}

// Route 对目标 dst 返回派发出站名(命中规则的 To,或 default)。栈上、零堆分配。
func (e *Engine) Route(dst addr.Socksaddr) string {
	best := ordNone
	if dst.IsFqdn() {
		host := normDomain(dst.Fqdn)
		if o, ok := e.exact[host]; ok && o < best {
			best = o
		}
		// 后缀:沿标签父链 a.b.c -> a.b.c -> b.c -> c 各查一次取 min(标签边界后缀)。
		for s := host; s != ""; {
			if o, ok := e.suffix[s]; ok && o < best {
				best = o
			}
			i := strings.IndexByte(s, '.')
			if i < 0 {
				break
			}
			s = s[i+1:]
		}
		for j := range e.keyword {
			if e.keyword[j].ord < best && strings.Contains(host, e.keyword[j].kw) {
				best = e.keyword[j].ord
			}
		}
		for j := range e.geosite {
			if e.geosite[j].ord < best && e.geosite[j].set.MatchDomain(host) {
				best = e.geosite[j].ord
			}
		}
	} else if dst.IsIP() {
		ip := dst.Addr.Unmap()
		for j := range e.cidr {
			if e.cidr[j].ord < best && e.cidr[j].p.Contains(ip) {
				best = e.cidr[j].ord
			}
		}
		for j := range e.geoip {
			if e.geoip[j].ord < best && e.geoip[j].set.MatchIP(ip) {
				best = e.geoip[j].ord
			}
		}
	}
	if o, ok := e.ports[dst.Port]; ok && o < best {
		best = o
	}
	if best == ordNone {
		return e.def
	}
	return e.targets[best]
}

// Default 返回兜底出站名。
func (e *Engine) Default() string { return e.def }

// putMin 把 k 的值更新为 min(现值, ord)。
func putMin[K comparable](m map[K]uint32, k K, ord uint32) {
	if o, ok := m[k]; !ok || ord < o {
		m[k] = ord
	}
}

// normDomain 归一化域名:小写 + 去尾点。
func normDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(d, "."))
}
