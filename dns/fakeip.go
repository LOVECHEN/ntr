package dns

// fake-ip:给域名分配一个「伪 IP」(默认 v4 198.18.0.0/15、v6 fc00::/18),让【只见 IP】的连接
// (TUN 捕获、IP 直连、不带域名的客户端)也能按域名分流 —— 查 DNS 拿伪 IP,连伪 IP 时反查回域名再路由。
// 双向映射 + 环形游标 + FIFO 回收(池满驱逐最旧)。伪 IP 不出本机(路由前就换回域名),绝不真拨。
// 语义对齐 sing-box/mihomo fake-ip:同域名稳定复用同一伪 IP;A→v4 池、AAAA→v6 池(无 v6 范围则 AAAA 空答)。

import (
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// FakeIPConfig 是 fake-ip 的对外配置(config 建好传入 dns.New)。Inet4/Inet6 至少一个有效。
type FakeIPConfig struct {
	Inet4   netip.Prefix // v4 伪 IP 段(默认 198.18.0.0/15)
	Inet6   netip.Prefix // v6 伪 IP 段(默认 fc00::/18);零值=不发 v6 伪 IP
	Exclude []string     // 排除域名后缀:命中则不 fake、走真解析(如 DNS 服务器自身域名)
}

type fakeIPPool struct {
	mu           sync.Mutex
	p4, p6       netip.Prefix
	have4, have6 bool
	cur4, cur6   netip.Addr
	d2v4, d2v6   map[string]netip.Addr // 域名 → 伪 IP(各族一份)
	ip2d         map[netip.Addr]string // 伪 IP → 域名(两族共用)
	exclude      []string              // 已规范化的排除后缀(小写、无尾点)
}

func newFakeIPPool(cfg *FakeIPConfig) *fakeIPPool {
	p := &fakeIPPool{
		d2v4: map[string]netip.Addr{},
		d2v6: map[string]netip.Addr{},
		ip2d: map[netip.Addr]string{},
	}
	for _, e := range cfg.Exclude {
		if s := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(e), ".")); s != "" {
			p.exclude = append(p.exclude, s)
		}
	}
	if cfg.Inet4.IsValid() && cfg.Inet4.Addr().Unmap().Is4() {
		p.p4 = cfg.Inet4.Masked()
		p.have4 = true
		p.cur4 = p.p4.Addr().Next() // 跳过网络地址(.0)
	}
	if cfg.Inet6.IsValid() && cfg.Inet6.Addr().Is6() && !cfg.Inet6.Addr().Is4In6() {
		p.p6 = cfg.Inet6.Masked()
		p.have6 = true
		p.cur6 = p.p6.Addr().Next()
	}
	return p
}

// excluded 判 name(小写、可带尾点)是否命中排除后缀(命中→不 fake)。
func (p *fakeIPPool) excluded(name string) bool {
	host := strings.TrimSuffix(name, ".")
	for _, suf := range p.exclude {
		if host == suf || strings.HasSuffix(host, "."+suf) {
			return true
		}
	}
	return false
}

// alloc 给 name(小写、可带尾点)按 qtype 分配/复用伪 IP。AAAA 但无 v6 段 → (zero,false)。
func (p *fakeIPPool) alloc(name string, qtype dnsmessage.Type) (netip.Addr, bool) {
	host := strings.TrimSuffix(name, ".")
	p.mu.Lock()
	defer p.mu.Unlock()
	switch qtype {
	case dnsmessage.TypeA:
		if !p.have4 {
			return netip.Addr{}, false
		}
		if ip, ok := p.d2v4[host]; ok {
			return ip, true
		}
		ip := p.cur4
		p.cur4 = wrapNext(p.cur4, p.p4)
		p.evictLocked(ip)
		p.d2v4[host] = ip
		p.ip2d[ip] = host
		return ip, true
	case dnsmessage.TypeAAAA:
		if !p.have6 {
			return netip.Addr{}, false
		}
		if ip, ok := p.d2v6[host]; ok {
			return ip, true
		}
		ip := p.cur6
		p.cur6 = wrapNext(p.cur6, p.p6)
		p.evictLocked(ip)
		p.d2v6[host] = ip
		p.ip2d[ip] = host
		return ip, true
	}
	return netip.Addr{}, false
}

// evictLocked 若 ip 已被占用,驱逐旧映射(FIFO 回收;调用方持锁)。
func (p *fakeIPPool) evictLocked(ip netip.Addr) {
	if old, ok := p.ip2d[ip]; ok {
		delete(p.ip2d, ip)
		if p.d2v4[old] == ip {
			delete(p.d2v4, old)
		}
		if p.d2v6[old] == ip {
			delete(p.d2v6, old)
		}
	}
}

// lookup 反查伪 IP → 域名(bare、小写)。非本池 IP → ("",false)。
func (p *fakeIPPool) lookup(ip netip.Addr) (string, bool) {
	ip = ip.Unmap()
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.ip2d[ip]
	return d, ok
}

// contains 判 ip 是否落在任一伪 IP 段(快速排除非 fake 段,免查 map)。
func (p *fakeIPPool) contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	return (p.have4 && p.p4.Contains(ip)) || (p.have6 && p.p6.Contains(ip))
}

// wrapNext 返回 ip 的下一地址;越出前缀则绕回首个可用地址(跳网络地址)。
func wrapNext(ip netip.Addr, pfx netip.Prefix) netip.Addr {
	n := ip.Next()
	if !n.IsValid() || !pfx.Contains(n) {
		return pfx.Addr().Next()
	}
	return n
}
