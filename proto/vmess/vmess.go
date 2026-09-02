// Package vmess 把 VMess(AEAD)接入 NTR 的统一协议插件契约。
//
// ★用第三方权威实现 github.com/metacubex/sing-vmess(与 Xray / mihomo / sing-box 互通)。
// VMess 是流式代理(DialConn 叠在下层 stream 上),故完全套 proxy.Server/Client 栈契约:
// 可裸跑或叠 [tls, vmess]。auth 靠 UUID(sing 内部处理),NTR 归 Ambient。
package vmess

import (
	"context"
	"fmt"
	"net"

	vmess "github.com/metacubex/sing-vmess"
	M "github.com/metacubex/sing/common/metadata"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/spec"
)

var (
	_ proxy.Server = (*Proxy)(nil)
	_ proxy.Client = (*Proxy)(nil)
)

// Config 是 VMess 自有配置。UUID 是用户身份;Security 是 AEAD 套件(auto/aes-128-gcm/
// chacha20-poly1305/none),默认 auto。AlterID 恒 0(纯 AEAD,MD5 旧协议已废)。
type Config struct {
	UUID     string
	Security string
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	sec := n.Get("security").Str()
	if sec == "" {
		sec = "auto"
	}
	return Config{UUID: n.Get("uuid").Str(), Security: sec}, nil
}

// Proxy 是 VMess 连接级句柄:客户端 Client + 服务端 Service 都在 Build 时建好。
type Proxy struct {
	cfg     Config
	client  *vmess.Client          // 出站用;入站口未写 uuid(凭据来自顶层 users)时为 nil
	service *vmess.Service[string] // 入站用;单用户口装 uuid,多用户口由 RegisterUsers 整批替换
	users   userRefs               // 顶层 users:tag → 归属(经 UserRegistrar 注入;空 = 单用户口)
}

var _ proxy.UserRegistrar = (*Proxy)(nil)

// Build 构造 Proxy。uuid 可空:入站口凭据来自顶层 users(第4章)时不写 uuid —— 此时不建客户端、
// 服务端等 RegisterUsers 注入;写了 uuid 则两端都建(旧写法 / 出站)。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	sec := cfg.Security
	if sec == "" {
		sec = "auto"
	}
	svc := vmess.NewService[string](captureHandler{})
	p := &Proxy{cfg: Config{UUID: cfg.UUID, Security: sec}, service: svc}
	if cfg.UUID != "" {
		client, err := vmess.NewClient(cfg.UUID, sec, 0)
		if err != nil {
			return nil, fmt.Errorf("vmess: 客户端失败:%w", err)
		}
		if err := svc.UpdateUsers([]string{"u"}, []string{cfg.UUID}, []int{0}); err != nil {
			return nil, fmt.Errorf("vmess: 服务端用户失败:%w", err)
		}
		p.client = client
	}
	return p, nil
}

// RegisterUsers 实现 proxy.UserRegistrar(第4章顶层 users 接入):VMess 的 authID 是时间加密,线上无明文
// key,多用户匹配只能在 sing-vmess 的 Service 内部完成 —— 整批 UpdateUsers(tag=BillID, uuid),命中后
// sing 以 auth.ContextWithUser(ctx, tag) 回调,server.go 按 tag 映回 cred.Ref。替换掉口内 uuid 的单用户集。
func (p *Proxy) RegisterUsers(users []proxy.RegisteredUser) error {
	tags := make([]string, len(users))
	uuids := make([]string, len(users))
	alter := make([]int, len(users))
	var refs userRefs
	for i, u := range users {
		tags[i], uuids[i] = u.Tag, u.Secret
		refs.set(u.Tag, u.Ref)
	}
	if err := p.service.UpdateUsers(tags, uuids, alter); err != nil {
		return fmt.Errorf("vmess: 注册顶层 users:%w", err)
	}
	p.users = refs
	return nil
}

// ClientHandshake 实现 proxy.Client:在下层 stream 上写 VMess 请求头,返回承载 payload 的 stream。
func (p *Proxy) ClientHandshake(_ context.Context, below link.Stream, _ []byte, dst addr.Socksaddr) (link.Stream, error) {
	if p.client == nil {
		return nil, fmt.Errorf("vmess: 出站须写 uuid(入站口才允许省略 uuid 由顶层 users 供凭据)")
	}
	conn, err := p.client.DialConn(below, toSing(dst))
	if err != nil {
		return nil, err
	}
	return &streamWrap{Conn: conn, below: below}, nil
}

func toSing(a addr.Socksaddr) M.Socksaddr {
	return M.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}
func toNTR(a M.Socksaddr) addr.Socksaddr {
	return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}

type streamWrap struct {
	net.Conn
	below any
}

func (s *streamWrap) Unwrap() any { return s.below }
