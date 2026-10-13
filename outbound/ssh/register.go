package ssh

import (
	"errors"
	"fmt"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// 会话式协议插件自注册(registry.RegisterSession):运行时按 type: ssh 查表,本包自解字段。
// 入站跑在 TCP 上,由运行时的 TCP 接入环托管监听(NewHandler 形态)。
//
// 出站字段:server / user(默认 root)/ secret(或 password)/ private-key / host-key。
// 入站:host 私钥 = tls 块的 key(key 或 key-file);用户 = 口令或公钥(顶层 users 写 keys.ssh 标量口令,
// 或结构化 {password, public-key};口内 users 写 password / public-key)。
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "ssh",
		NewOutbound:     newOutboundFromNode,
		NewHandler:      newHandlerFromSession,
		UserFromContext: UserFromContext,
	})
}

func newOutboundFromNode(n *spec.Node) (endpoint.Outbound, error) {
	pw := n.Get("password").Str()
	if pw == "" {
		pw = n.Get("secret").Str()
	}
	return NewOutbound(Options{
		Server:     n.Get("server").Str(),
		User:       n.Get("user").Str(),
		Password:   pw,
		PrivateKey: n.Get("private-key").Str(),
		HostKey:    n.Get("host-key").Str(),
	})
}

func newHandlerFromSession(in registry.SessionInbound) (endpoint.InboundHandler, error) {
	if in.TLSKey == "" {
		return nil, errors.New("ssh 入站需 tls.key(host 私钥 PEM)")
	}
	users := make([]User, 0, len(in.Users))
	for _, u := range in.Users {
		pw := u.Fields["password"]
		if pw == "" {
			pw = u.Secret
		}
		pk := u.Fields["public-key"]
		if pw == "" && pk == "" {
			return nil, fmt.Errorf("ssh: 用户 %q 缺 password/public-key", u.Tag)
		}
		users = append(users, User{Name: u.Tag, Password: pw, PublicKey: pk})
	}
	if len(users) == 0 {
		return nil, errors.New("ssh 入站需至少一个用户(顶层 users.keys.ssh{password/public-key} 或口内 user)")
	}
	return NewInbound(users, in.TLSKey, in.Out, in.Dispatch)
}
