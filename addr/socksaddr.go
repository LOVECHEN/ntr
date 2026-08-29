// Package addr 提供代理寻址的逻辑目标类型 Socksaddr —— 可为域名或 IP,带端口。
//
// 这是四形状数据面里 PacketConn / Metadata 的"目标可为域名"载体(承设计第 2 章
// §2.1):代理必须能表达"发往 example.com:443"这个尚未解析的域名,而不是被 net.Addr
// 逼着提前解析(那会丢失域名、破坏 fake-ip 与域名路由)。
package addr

import (
	"net"
	"net/netip"
	"strconv"
)

// Socksaddr 是域名或 IP 二选一的带端口地址。IsFqdn 与 IsIP 互斥。
type Socksaddr struct {
	Addr netip.Addr // IP 形态时有效
	Fqdn string     // 域名形态时非空
	Port uint16
}

// FromIPPort 由 netip.AddrPort 构造 IP 形态地址。
func FromIPPort(ap netip.AddrPort) Socksaddr {
	return Socksaddr{Addr: ap.Addr(), Port: ap.Port()}
}

// FromFqdn 构造域名形态地址。
func FromFqdn(fqdn string, port uint16) Socksaddr {
	return Socksaddr{Fqdn: fqdn, Port: port}
}

// IsFqdn 报告是否为域名形态。
func (s Socksaddr) IsFqdn() bool { return s.Fqdn != "" }

// IsIP 报告是否为 IP 形态。
func (s Socksaddr) IsIP() bool { return s.Fqdn == "" && s.Addr.IsValid() }

// IsValid 报告是否为有效地址(域名或 IP 之一)。
func (s Socksaddr) IsValid() bool { return s.IsFqdn() || s.IsIP() }

// Host 返回域名或 IP 字符串(不含端口)。
func (s Socksaddr) Host() string {
	if s.IsFqdn() {
		return s.Fqdn
	}
	return s.Addr.String()
}

// String 返回 host:port。
func (s Socksaddr) String() string {
	if s.IsFqdn() {
		return net.JoinHostPort(s.Fqdn, strconv.Itoa(int(s.Port)))
	}
	return netip.AddrPortFrom(s.Addr, s.Port).String()
}
