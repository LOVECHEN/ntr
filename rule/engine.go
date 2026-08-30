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
	"slices"
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

// ProcessFinder 由连接源地址反查【发起该连接的本机进程】(process 规则的抽象;实现在 service 的
// 进程反查包,读 /proc 或 libproc —— rule 只认接口、不碰平台 I/O,合插件门禁)。
// ok=false 表示查不到(非本机发起 / 进程已退出 / 平台不支持)—— 此时 process 规则一律不命中。
type ProcessFinder interface {
	FindProcess(network string, src netip.AddrPort) (name, path string, ok bool)
}

// Rule 是一条规则:恰好【一个】维度谓词非空 + 目标 To(出站/链名)。ord 由 Compile 按声明序赋。
type Rule struct {
	Domain        []string    // 精确域名(exact)
	DomainSuffix  []string    // 域名后缀(按标签边界)
	DomainKeyword []string    // 域名子串
	IPCIDR        []string    // CIDR 前缀(仅对 IP 目标)
	Port          []uint16    // 目标端口
	Network       []string    // 传输层网络(tcp/udp)
	GeoIP         []IPSet     // geoip 国码集合(仅对 IP 目标;由 config 从 mmdb 建好传入)
	GeoSite       []DomainSet // geosite 域名集合(仅对域名目标;由 config 从 geosite.dat 建好传入)
	ProcessName   []string    // 发起进程可执行名(basename,精确;仅对本机入站有意义)
	ProcessPath   []string    // 发起进程可执行完整路径(精确)

	// 逻辑组合(v2):Op 非空 → 本规则是【组合规则】,叶子维度须全空、Sub 为子规则列表。
	//   and = 全部子规则命中;or = 任一命中;Not 对组合结果取反(= NOT)。子规则可再嵌套组合。
	// 对齐 sing-box logical(and/or + invert)、mihomo/xray AND/OR/NOT。
	Op  string // "" =叶子(单维度);"and"/"or" =组合
	Sub []Rule // 组合规则的子规则(叶子或嵌套组合;子规则不带 To)
	Not bool   // 组合结果取反(NOT)

	To string // 命中后派发到的出站/链名(组合规则也用)
}

// dimCount 返回本规则设了几个维度(须恰好 1)。
func (r *Rule) dimCount() int {
	n := 0
	for _, nonEmpty := range []bool{
		len(r.Domain) > 0, len(r.DomainSuffix) > 0, len(r.DomainKeyword) > 0,
		len(r.IPCIDR) > 0, len(r.Port) > 0, len(r.Network) > 0, len(r.GeoIP) > 0, len(r.GeoSite) > 0,
		len(r.ProcessName) > 0, len(r.ProcessPath) > 0,
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
	targets  []string          // ord -> 目标名
	def      string            // 未命中兜底
	exact    map[string]uint32 // 精确域名 -> min ord
	suffix   map[string]uint32 // 后缀标签串 -> min ord
	keyword  []kwEntry         // 子串,逐个点查(逻辑上是残余,但常用故单列)
	cidr     []cidrEntry       // CIDR,逐个点查取 min(路径全收集,非最长前缀)
	geoip    []geoEntry        // geoip 集合,逐个 MatchIP 取 min(仅 IP 目标)
	geosite  []siteEntry       // geosite 集合,逐个 MatchDomain 取 min(仅域名目标)
	ports    map[uint16]uint32 // 端口 -> min ord
	netw     map[string]uint32 // 网络 tcp/udp -> min ord
	procName map[string]uint32 // 进程 basename -> min ord
	procPath map[string]uint32 // 进程完整路径 -> min ord
	hasProc  bool              // 是否有 process 规则(无则 RouteConn 跳过进程反查,省 I/O)

	logical    []evalRule // 逻辑组合规则(and/or/not),顺序求值取命中 min ord
	hasLogical bool       // 是否有组合规则
}

// evalRule 是一条编译后的组合规则:eval(命中判定)+ ord(声明序)。
type evalRule struct {
	eval func(*evalCtx) bool
	ord  uint32
}

// evalCtx 是一次路由的求值上下文:dst + 源(供 process 子规则)。进程反查 lazy、整次路由至多一次。
type evalCtx struct {
	dst      addr.Socksaddr
	src      netip.AddrPort
	network  string
	finder   ProcessFinder
	procDone bool
	procName string
	procPath string
	procOK   bool
}

// proc 反查发起进程(lazy,缓存本次路由结果)。finder nil / src 无效 → ok=false。
func (c *evalCtx) proc() (name, path string, ok bool) {
	if !c.procDone {
		c.procDone = true
		if c.finder != nil && c.src.IsValid() {
			c.procName, c.procPath, c.procOK = c.finder.FindProcess(c.network, c.src)
		}
	}
	return c.procName, c.procPath, c.procOK
}

// Compile 把有序规则表 + default 编成 Engine。纯函数、无 I/O(承 §4.6 Compile 阶段)。
// 校验:每条规则恰好一个维度;CIDR 可解析;default 非空。
func Compile(rules []Rule, def string) (*Engine, error) {
	if def == "" {
		return nil, fmt.Errorf("rule: routing.default 不可为空(未命中兜底出站)")
	}
	e := &Engine{
		def:      def,
		targets:  make([]string, len(rules)),
		exact:    map[string]uint32{},
		suffix:   map[string]uint32{},
		ports:    map[uint16]uint32{},
		netw:     map[string]uint32{},
		procName: map[string]uint32{},
		procPath: map[string]uint32{},
	}
	for i := range rules {
		r := &rules[i]
		if r.To == "" {
			return nil, fmt.Errorf("rule[%d]: 缺 to(目标出站)", i)
		}
		ord := uint32(i)
		e.targets[i] = r.To
		// 组合规则(and/or/not):单独编成 evaluator,不进各维度索引。
		if r.Op != "" {
			if err := validateComposite(r); err != nil {
				return nil, fmt.Errorf("rule[%d]:%w", i, err)
			}
			e.logical = append(e.logical, evalRule{eval: compileEval(r), ord: ord})
			e.hasLogical = true
			continue
		}
		if n := r.dimCount(); n != 1 {
			return nil, fmt.Errorf("rule[%d]: 须恰好一个维度谓词,实为 %d(组合规则请用 op: and/or)", i, n)
		}
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
		for _, nw := range r.Network {
			if nw != "tcp" && nw != "udp" {
				return nil, fmt.Errorf("rule[%d]: network %q 须为 tcp/udp", i, nw)
			}
			putMin(e.netw, nw, ord)
		}
		for _, gs := range r.GeoIP {
			e.geoip = append(e.geoip, geoEntry{gs, ord})
		}
		for _, ds := range r.GeoSite {
			e.geosite = append(e.geosite, siteEntry{ds, ord})
		}
		for _, pn := range r.ProcessName {
			putMin(e.procName, pn, ord)
			e.hasProc = true
		}
		for _, pp := range r.ProcessPath {
			putMin(e.procPath, pp, ord)
			e.hasProc = true
		}
	}
	return e, nil
}

// validateComposite 校验组合规则(递归):op∈{and,or}、sub 非空、无叶子维度、子规则合法且不带 to。
func validateComposite(r *Rule) error {
	if r.Op != "and" && r.Op != "or" {
		return fmt.Errorf("组合规则 op %q 须为 and/or", r.Op)
	}
	if len(r.Sub) == 0 {
		return fmt.Errorf("组合规则 sub 不可为空")
	}
	if r.dimCount() != 0 {
		return fmt.Errorf("组合规则不可同时带叶子维度谓词(维度应写在 sub 子规则里)")
	}
	for i := range r.Sub {
		s := &r.Sub[i]
		if s.To != "" {
			return fmt.Errorf("子规则不可带 to(只有顶层规则派发出站)")
		}
		if s.Op != "" {
			if err := validateComposite(s); err != nil {
				return err
			}
		} else if s.dimCount() != 1 {
			return fmt.Errorf("子规则须恰好一个维度谓词或为嵌套组合,实为 %d 维度", s.dimCount())
		}
	}
	return nil
}

// compileEval 把组合规则编成命中判定闭包(递归)。叶子 → matchLeaf;and/or → 折叠子判定;Not → 取反。
func compileEval(r *Rule) func(*evalCtx) bool {
	if r.Op == "" {
		leaf := r
		return func(c *evalCtx) bool { return matchLeaf(leaf, c) }
	}
	subs := make([]func(*evalCtx) bool, len(r.Sub))
	for i := range r.Sub {
		subs[i] = compileEval(&r.Sub[i])
	}
	var f func(*evalCtx) bool
	switch r.Op {
	case "and":
		f = func(c *evalCtx) bool {
			for _, s := range subs {
				if !s(c) {
					return false
				}
			}
			return true
		}
	default: // "or"
		f = func(c *evalCtx) bool {
			for _, s := range subs {
				if s(c) {
					return true
				}
			}
			return false
		}
	}
	if r.Not {
		inner := f
		f = func(c *evalCtx) bool { return !inner(c) }
	}
	return f
}

// matchLeaf 判定单维度叶子规则是否命中(供组合规则求值;含 process,lazy 反查)。
func matchLeaf(r *Rule, c *evalCtx) bool {
	dst := c.dst
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
		for _, ds := range r.GeoSite {
			if ds.MatchDomain(host) {
				return true
			}
		}
	}
	if dst.IsIP() {
		ip := dst.Addr.Unmap()
		for _, cc := range r.IPCIDR {
			if p, err := netip.ParsePrefix(cc); err == nil && p.Masked().Contains(ip) {
				return true
			}
		}
		for _, gs := range r.GeoIP {
			if gs.MatchIP(ip) {
				return true
			}
		}
	}
	if slices.Contains(r.Port, dst.Port) {
		return true
	}
	if len(r.ProcessName) > 0 || len(r.ProcessPath) > 0 {
		if name, path, ok := c.proc(); ok {
			if slices.Contains(r.ProcessName, name) || slices.Contains(r.ProcessPath, path) {
				return true
			}
		}
	}
	return false
}

// Route 对目标 dst 返回派发出站名(命中规则的 To,或 default)。无 network / 源上下文,network 与
// 组合/进程里需要源的部分不参与匹配;带 network 请用 RouteConn。
func (e *Engine) Route(dst addr.Socksaddr) string {
	return e.RouteConn(dst, netip.AddrPort{}, "", nil)
}

// HasProcess 报告是否配了 process 规则(上游据此决定是否需要源侧进程反查)。
func (e *Engine) HasProcess() bool { return e.hasProc }

// RouteConn 带源上下文路由:先匹配 dst 侧维度,再(仅当有 process 规则且 finder 非 nil)据 src+network
// 反查发起进程,把 process 命中并入 min-ordinal。finder 为 nil 或无 process 规则时等价 Route(dst)。
// 进程反查有 I/O 成本,故仅在 hasProc 时触发、admission 期一次、离字节路径。
func (e *Engine) RouteConn(dst addr.Socksaddr, src netip.AddrPort, network string, finder ProcessFinder) string {
	best := e.dimsBest(dst, network)
	// 顶层 process 叶子规则:走 map 索引(快)。组合规则里的 process 子规则走 evalCtx.proc()。
	var ctx *evalCtx
	if (e.hasProc || e.hasLogical) && finder != nil && src.IsValid() {
		ctx = &evalCtx{dst: dst, src: src, network: network, finder: finder}
	}
	if e.hasProc && ctx != nil {
		if name, path, ok := ctx.proc(); ok {
			if o, ok2 := e.procName[name]; ok2 && o < best {
				best = o
			}
			if o, ok2 := e.procPath[path]; ok2 && o < best {
				best = o
			}
		}
	}
	if e.hasLogical {
		if ctx == nil { // 无源(纯 dst 路由):组合规则里的 process 子规则将不命中
			ctx = &evalCtx{dst: dst, src: src, network: network, finder: finder}
		}
		for i := range e.logical {
			if e.logical[i].ord < best && e.logical[i].eval(ctx) {
				best = e.logical[i].ord
			}
		}
	}
	if best == ordNone {
		return e.def
	}
	return e.targets[best]
}

// dimsBest 返回 dst 侧各维度(含 network)命中的最小 ord(ordNone=未命中)。Route/RouteConn 共用。
func (e *Engine) dimsBest(dst addr.Socksaddr, network string) uint32 {
	best := ordNone
	if network != "" {
		if o, ok := e.netw[network]; ok && o < best {
			best = o
		}
	}
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
	return best
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
