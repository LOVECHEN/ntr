//go:build !with_connectip

package connectip

import (
	"context"
	"errors"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

// 默认构建【不含】CONNECT-IP 出站:它需要用户态 netstack(gVisor),与瘦核心默认形态冲突。
// 需要时:go build -tags with_connectip ./cmd/ntr
// 注:capsule.go / datagram.go 是纯编解码零依赖,不在 build tag 之后,始终可用。

var _ endpoint.Outbound = (*Outbound)(nil)

// ErrNotBuilt 表示当前二进制未编入 CONNECT-IP 支持。
var ErrNotBuilt = errors.New("connect-ip: 本二进制未编入 CONNECT-IP 支持(需 -tags with_connectip 重新构建)")

// Options 与真实现同名同字段,使 config 接线在两种构建下一致。
type Options struct {
	Server                string
	SNI                   string
	Insecure              bool
	Protocol              string
	URITemplate           string
	ExtraSettings         map[uint64]uint64
	IgnoreExtendedConnect bool
	LocalAddress          []string
	DNS                   []string
	MTU                   int
	ClientCert            string
	ClientKey             string
}

// Outbound 是未编入时的占位类型。
type Outbound struct{}

// NewOutbound 在未编入时直接报错,不静默降级。
func NewOutbound(Options) (*Outbound, error) { return nil, ErrNotBuilt }

func (*Outbound) DialStream(context.Context, addr.Socksaddr) (link.Stream, error) {
	return nil, ErrNotBuilt
}
func (*Outbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, ErrNotBuilt
}
func (*Outbound) Close() error { return nil }

// InboundOptions 与真实现同名同字段。
type InboundOptions struct {
	AssignAddress string
	MTU           int
	ExtraSettings map[uint64]uint64
}

// Inbound 是未编入时的占位类型。
type Inbound struct{}

// NewInbound 在未编入时直接报错。tlsConfig 用 any 以免 stub 引入 metacubex/tls。
func NewInbound(InboundOptions, any, endpoint.Outbound) (*Inbound, error) { return nil, ErrNotBuilt }

// Run 在未编入时直接报错。
func (*Inbound) Run(context.Context, string) error { return ErrNotBuilt }
