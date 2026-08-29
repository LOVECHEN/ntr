//go:build !with_tun

// TUN 入站默认不编入(gVisor 用户态栈体积大)。需 -tags with_tun 重新构建。stub 保证 config 两态可链接。
package tun

import (
	"context"
	"errors"
	"net/netip"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/route"
)

// ErrNotBuilt 表示本二进制未编入 TUN 支持。
var ErrNotBuilt = errors.New("tun: 本二进制未编入 TUN 支持(需 -tags with_tun 重新构建)")

// Options 与真实现同名同字段。
type Options struct {
	Name      string
	Address   []string
	MTU       int
	Resolver  route.Resolver
	HijackDNS []netip.AddrPort
}

// Inbound 占位。
type Inbound struct{}

// NewInbound 占位:无 tag 时报错。
func NewInbound(_ Options, _ endpoint.Outbound) (*Inbound, error) { return nil, ErrNotBuilt }

// Run 占位。
func (*Inbound) Run(context.Context, string) error { return ErrNotBuilt }
