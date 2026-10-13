package mieru

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/LOVECHEN/ntr/addr"
)

// ipOnly 保证 mieru UDP-associate 包头只出现 IP:官方 UDPAssociateWrapper 收到带 FQDN 的头直接报
// 「peer used FQDN in UDP associate header, which is unsupported」丢包(线格式约束,两端皆然)。
// mihomo 客户端发出前先解析,故与之交叉测不出;NTR 两端都要自守:IP 字面量(socks5 客户端常以
// ATYP=3 发 "1.2.3.4")直接解析,真域名查一次 DNS 后按会话缓存。
type ipOnly struct {
	mu sync.Mutex
	m  map[string]netip.Addr
}

var errNoIP = errors.New("mieru: UDP 目标域名解析无结果")

func (c *ipOnly) resolve(a addr.Socksaddr) (addr.Socksaddr, error) {
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
