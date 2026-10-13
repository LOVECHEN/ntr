package shadowquic

import (
	"errors"
	"fmt"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// 会话式协议插件自注册(registry.RegisterSession):运行时按 type: shadowquic 查表,本包自解字段。
// 入站跑在 JLS-over-QUIC(UDP)上,自管监听(NewInbound → Runner)。
//
// 出站字段:server / user / secret(或 password)/ sni(JLS ServerName,缺省取 server host)。
// 入站:sni 取 tls 块的 sni(须与客户端 servername 一致);target 兜底推导 sni。用户 = JLS PSK 用户名 + 口令,
// ★用户名 = 计量 tag(握手 ConnectionState().TLS.JLS.User 回读的正是它),故顶层 users 的 keys.shadowquic
// 只写口令;口内 users 写 username/password。
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "shadowquic",
		NewOutbound:     newOutboundFromNode,
		NewInbound:      newInboundFromSession,
		UserFromContext: UserFromContext,
	})
}

func newOutboundFromNode(n *spec.Node) (endpoint.Outbound, error) {
	pw := n.Get("password").Str()
	if pw == "" {
		pw = n.Get("secret").Str()
	}
	return NewOutbound(Options{
		Server:   n.Get("server").Str(),
		Username: n.Get("user").Str(),
		Password: pw,
		SNI:      n.Get("sni").Str(),
	})
}

func newInboundFromSession(in registry.SessionInbound) (registry.Runner, error) {
	users := make([]User, 0, len(in.Users))
	for _, u := range in.Users {
		name := u.Fields["username"] // 口内写法用 username;顶层 users 的用户名即 tag
		if name == "" {
			name = u.Tag
		}
		if name == "" {
			continue
		}
		pw := u.Fields["password"]
		if pw == "" {
			pw = u.Secret
		}
		if pw == "" {
			return nil, fmt.Errorf("shadowquic: 用户 %q 缺口令(顶层 users 写 keys.shadowquic,口内 users 写 password)", name)
		}
		users = append(users, User{Username: name, Password: pw})
	}
	if len(users) == 0 {
		return nil, errors.New("shadowquic 入站需至少一个用户(顶层 users.keys.shadowquic{password} 或口内 user{username,password})")
	}
	return NewInbound(users, in.TLSNode.Get("sni").Str(), in.Node.Get("target").Str(), nil, in.Out, in.Dispatch)
}
