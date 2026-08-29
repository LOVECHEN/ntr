// Package dns 是 DNS 解析子系统(承设计 §10.1),住在 core 外(与 rule/ 同级),经 core/route.Resolver
// 接口被 admission(路由)与内置 dns 出站消费。MVP:明文 UDP/TCP 上游 + 纯内存 TTL 缓存 + race/sequential
// 策略,每上游强制绑定具名出站(detour,防 DNS 泄漏)。DoH/DoT/DoQ、fake-ip、policy 为 Phase 2。
//
// ★全热:解析计划(nameservers/strategy)存 atomic.Pointer[plan] —— reload 换指针,in-flight 查询跑完旧代,
// 数据连接零断(承设计"全热系统架构")。缓存跨代存活、纯内存、绝不落盘。
package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/route"
)

// ErrDisabled:dns 子系统未启用时 Lookup/Exchange 大声报(承冻结律 #9,绝不静默直连)。
var ErrDisabled = errors.New("dns: 子系统未启用(dns.enabled=false)")

// ErrAllUpstreamsFailed:组内全部上游失败(绝不把"解析不出"当"空集成功")。
var ErrAllUpstreamsFailed = errors.New("dns: 组内全部上游失败/超时/空答")

type strat uint8

const (
	stratRace strat = iota
	stratSequential
)

type plan struct {
	nameservers []*upstream
	strategy    strat
	hosts       *hostsMap // 静态 host→IP,命中不走上游
}

// Resolver 实现 route.Resolver。
type Resolver struct {
	p     atomic.Pointer[plan]
	cache *cache
	fake  *fakeIPPool // fake-ip 池(nil=未启用);跨 reload 存活(伪 IP 映射不能丢),故挂 Resolver 非 plan
}

var _ route.Resolver = (*Resolver)(nil)

// Nameserver 是一台上游的配置(detour 已在 config 期解析成具名出站,防 DNS 泄漏)。
type Nameserver struct {
	Tag      string
	Address  string // udp://IP:53 · tcp://IP:53 · tls://IP:853 · https://IP/dns-query
	SNI      string // DoT/DoH 的 TLS ServerName(可空 → 取地址 host)
	Insecure bool   // DoT/DoH 跳过证书校验(自签/测试)
	Detour   endpoint.Outbound
}

// buildPlan 把 Nameserver 配置解析成运行时 plan(解析承载 + 地址)。
func buildPlan(nss []Nameserver, strategy string, hosts map[string][]netip.Addr) (*plan, error) {
	if len(nss) == 0 {
		return nil, errors.New("dns: 至少需一个 nameserver")
	}
	st := stratRace
	switch strategy {
	case "", "race":
		st = stratRace
	case "sequential":
		st = stratSequential
	default:
		return nil, fmt.Errorf("dns: 未知 strategy %q(仅 race/sequential)", strategy)
	}
	var ups []*upstream
	for _, ns := range nss {
		if ns.Detour == nil {
			return nil, fmt.Errorf("dns: nameserver %q 缺 detour 出站(绝不隐式直连)", ns.Tag)
		}
		u, err := parseNameserver(ns.Address, ns.SNI, ns.Insecure)
		if err != nil {
			return nil, err
		}
		u.tag = ns.Tag
		u.detour = ns.Detour
		ups = append(ups, &u)
	}
	return &plan{nameservers: ups, strategy: st, hosts: newHosts(hosts)}, nil
}

// New 建解析器。fake 非 nil 则启用 fake-ip(伪 IP 映射跨 reload 存活)。
func New(nameservers []Nameserver, strategy string, hosts map[string][]netip.Addr, fake *FakeIPConfig) (*Resolver, error) {
	pl, err := buildPlan(nameservers, strategy, hosts)
	if err != nil {
		return nil, err
	}
	r := &Resolver{cache: newCache()}
	if fake != nil {
		r.fake = newFakeIPPool(fake)
	}
	r.p.Store(pl)
	return r, nil
}

// Reload 原子换代(全热:in-flight 查询跑完旧代,缓存跨代存活)。
func (r *Resolver) Reload(nameservers []Nameserver, strategy string, hosts map[string][]netip.Addr) error {
	pl, err := buildPlan(nameservers, strategy, hosts)
	if err != nil {
		return err
	}
	r.p.Store(pl)
	return nil
}

// Exchange 整报文进出:缓存优先,miss 经策略查上游,成功按 min-TTL 入缓存。
func (r *Resolver) Exchange(ctx context.Context, q *route.Message) (*route.Message, error) {
	p := r.p.Load()
	if p == nil {
		return nil, ErrDisabled
	}
	key, id, ok := parseQuery(q.Raw)
	if ok && p.hosts != nil {
		if addrs, hit := p.hosts.lookup(key.name, key.qtype); hit {
			if raw := buildHostsResponse(id, key.name, key.qtype, addrs); raw != nil {
				return &route.Message{Raw: raw}, nil
			}
		}
	}
	// fake-ip:A/AAAA 且未排除 → 就地合成伪 IP 应答(记映射),不走上游、不入缓存(池即缓存)。
	// hosts 优先于 fake(上面已判);AAAA 无 v6 段 → 空答(NOERROR 无记录),逼客户端用 v4 伪 IP、防 v6 泄漏。
	if ok && r.fake != nil && (key.qtype == dnsmessage.TypeA || key.qtype == dnsmessage.TypeAAAA) && !r.fake.excluded(key.name) {
		if fip, got := r.fake.alloc(key.name, key.qtype); got {
			if raw := buildHostsResponse(id, key.name, key.qtype, []netip.Addr{fip}); raw != nil {
				return &route.Message{Raw: raw}, nil
			}
		} else if key.qtype == dnsmessage.TypeAAAA { // 有 fake 但无 v6 段:AAAA 空答
			if raw := buildHostsResponse(id, key.name, key.qtype, nil); raw != nil {
				return &route.Message{Raw: raw}, nil
			}
		}
	}
	if ok {
		if cached, hit := r.cache.get(key); hit {
			setTxID(cached, id)
			return &route.Message{Raw: cached}, nil
		}
	}
	resp, err := p.exchange(ctx, q.Raw)
	if err != nil {
		return nil, err
	}
	if ok {
		if ttl, hasTTL := minTTL(resp); hasTTL {
			r.cache.put(key, resp, ttl)
		}
	}
	return &route.Message{Raw: resp}, nil
}

// exchange 按策略向上游发查询。
func (p *plan) exchange(ctx context.Context, raw []byte) ([]byte, error) {
	if p.strategy == stratSequential {
		var last error
		for _, u := range p.nameservers {
			resp, err := u.query(ctx, raw)
			if err == nil {
				return resp, nil
			}
			last = err
		}
		return nil, fmt.Errorf("%w:%v", ErrAllUpstreamsFailed, last)
	}
	// race:并发竞速,第一个成功胜出,其余 cancel。
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		raw []byte
		err error
	}
	ch := make(chan res, len(p.nameservers))
	var wg sync.WaitGroup
	for _, u := range p.nameservers {
		wg.Add(1)
		go func(u *upstream) {
			defer wg.Done()
			resp, err := u.query(rctx, raw)
			ch <- res{resp, err}
		}(u)
	}
	go func() { wg.Wait(); close(ch) }()
	var last error
	for r := range ch {
		if r.err == nil {
			return r.raw, nil
		}
		last = r.err
	}
	return nil, fmt.Errorf("%w:%v", ErrAllUpstreamsFailed, last)
}

// Lookup 解析 host 的 A/AAAA(缓存优先;miss 走上游)。
func (r *Resolver) Lookup(ctx context.Context, host string, s route.Strategy) ([]netip.Addr, error) {
	if r.p.Load() == nil {
		return nil, ErrDisabled
	}
	var addrs []netip.Addr
	for _, qt := range queryTypes(s) {
		raw, err := buildQuery(host, qt)
		if err != nil {
			return nil, err
		}
		resp, err := r.Exchange(ctx, &route.Message{Raw: raw})
		if err != nil {
			return nil, err
		}
		if na, ok := parseAddrs(resp.Raw); ok {
			addrs = append(addrs, toNetip(na)...)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("dns: %q 无 A/AAAA 记录", host)
	}
	return addrs, nil
}

// LookupCached 只查缓存(非阻塞快路径)。
func (r *Resolver) LookupCached(host string, s route.Strategy) ([]netip.Addr, bool) {
	var addrs []netip.Addr
	for _, qt := range queryTypes(s) {
		key := qkey{name: dnsName(host), qtype: qt}
		if raw, hit := r.cache.get(key); hit {
			if na, ok := parseAddrs(raw); ok {
				addrs = append(addrs, toNetip(na)...)
			}
		}
	}
	return addrs, len(addrs) > 0
}

// FakeIPToDomain 反查伪 IP → 域名(bare、小写);未启用 fake-ip 或非本池 IP → ("",false)。
func (r *Resolver) FakeIPToDomain(ip netip.Addr) (string, bool) {
	if r.fake == nil {
		return "", false
	}
	return r.fake.lookup(ip)
}

// ---- 小工具 ----

func queryTypes(s route.Strategy) []dnsmessage.Type {
	switch s {
	case route.StratV4Only:
		return []dnsmessage.Type{dnsmessage.TypeA}
	case route.StratV6Only:
		return []dnsmessage.Type{dnsmessage.TypeAAAA}
	case route.StratPreferV6:
		return []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeA}
	default:
		return []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	}
}

func dnsName(host string) string {
	if len(host) == 0 || host[len(host)-1] != '.' {
		host += "."
	}
	return dnsLower(host)
}

func dnsLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func buildQuery(host string, qt dnsmessage.Type) ([]byte, error) {
	name, err := dnsmessage.NewName(dnsName(host))
	if err != nil {
		return nil, fmt.Errorf("dns: 域名 %q 非法:%w", host, err)
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qt, Class: dnsmessage.ClassINET}},
	}
	return m.Pack()
}

func toNetip(na []netAddr) []netip.Addr {
	out := make([]netip.Addr, 0, len(na))
	for _, a := range na {
		if a.v4 {
			out = append(out, netip.AddrFrom4(a.a4))
		} else {
			out = append(out, netip.AddrFrom16(a.a16))
		}
	}
	return out
}
