//go:build !linux

// 非 Linux:透明代理(redirect/tproxy)依赖 Linux netfilter,提供占位以便 config 跨平台编译。
package transparent

import (
	"context"
	"errors"

	"github.com/LOVECHEN/ntr/core/endpoint"
)

// ErrNotSupported:透明代理仅 Linux 可用。
var ErrNotSupported = errors.New("transparent: redirect/tproxy 仅 Linux 支持")

// Options 与 Linux 版同字段(两态可链接)。
type Options struct {
	Mode    string
	Network []string
}

// Inbound 占位。
type Inbound struct{}

// NewInbound 在非 Linux 平台直接报错。
func NewInbound(Options, endpoint.Outbound) (*Inbound, error) { return nil, ErrNotSupported }

// Run 占位。
func (*Inbound) Run(context.Context, string) error { return ErrNotSupported }
