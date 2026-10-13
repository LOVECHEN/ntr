// Package ipresolve 给「UDP 包头只许 IP」的协议(mieru UDP-associate、TrustTunnel _udp2 …)把 FQDN 目标/来源
// 还原成 IP:IP 字面量(socks5 客户端常以 ATYP=3 发 "1.2.3.4")直接解析,真域名查一次 DNS 后按会话缓存。
package ipresolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/LOVECHEN/ntr/addr"
)

// Cache 是按会话的域名 → IP 缓存(零值可用,并发安全)。
type Cache struct {
	mu sync.Mutex
	m  map[string]netip.Addr
}

var errNoIP = errors.New("UDP 目标域名解析无结果")

// Resolve 返回 a 的 IP 形式(已是 IP 原样返回)。
func (c *Cache) Resolve(a addr.Socksaddr) (addr.Socksaddr, error) {
	if !a.IsFqdn() {
		return a, nil
	}
	if ip, err := netip.ParseAddr(a.Fqdn); err == nil {
		return addr.FromIPPort(netip.AddrPortFrom(ip.Unmap(), a.Port)), nil
	}
	c.mu.Lock()
	ip, ok := c.m[a.Fqdn]
	c.mu.Unlock()
	if !ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", a.Fqdn)
		cancel()
		if err != nil {
			return addr.Socksaddr{}, err
		}
		if len(ips) == 0 {
			return addr.Socksaddr{}, errNoIP
		}
		ip = ips[0].Unmap()
		for _, x := range ips { // 优先 IPv4(与多数 UDP 目标/对端栈更兼容)
			if x.Unmap().Is4() {
				ip = x.Unmap()
				break
			}
		}
		c.mu.Lock()
		if c.m == nil {
			c.m = make(map[string]netip.Addr)
		}
		c.m[a.Fqdn] = ip
		c.mu.Unlock()
	}
	return addr.FromIPPort(netip.AddrPortFrom(ip, a.Port)), nil
}
