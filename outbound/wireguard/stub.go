//go:build !with_wireguard

// Package wireguard 的占位实现:默认构建【不含】WireGuard。
//
// WireGuard 需要 golang.zx2c4.com/wireguard + 其 tun/netstack(内含 gVisor 用户态协议栈),
// 体积与依赖与 NTR 瘦核心的默认形态冲突,故置于 build tag 之后。
// 需要时:go build -tags with_wireguard ./cmd/ntr
package wireguard

import (
	"context"
	"errors"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = (*Outbound)(nil)

// ErrNotBuilt 表示当前二进制未编入 WireGuard 支持。
var ErrNotBuilt = errors.New("wireguard: 本二进制未编入 WireGuard 支持(需 -tags with_wireguard 重新构建)")

// Options 与真实现保持同名同字段,使 config 接线在两种构建下一致。
type Options struct {
	PrivateKey    string
	PeerPublicKey string
	PresharedKey  string
	Endpoint      string
	LocalAddress  []string
	AllowedIPs    []string
	DNS           []string
	MTU           int
	Keepalive     int
}

// Outbound 是未编入时的占位类型。
type Outbound struct{}

// NewOutbound 在未编入时直接报错,而不是静默降级。
func NewOutbound(Options) (*Outbound, error) { return nil, ErrNotBuilt }

func (*Outbound) DialStream(context.Context, addr.Socksaddr) (link.Stream, error) {
	return nil, ErrNotBuilt
}
func (*Outbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, ErrNotBuilt
}
func (*Outbound) Close() error { return nil }
