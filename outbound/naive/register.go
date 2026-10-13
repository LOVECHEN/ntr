package naive

import (
	"errors"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// 会话式协议插件自注册(registry.RegisterSession):运行时按 type: naive 查表,本包自解字段。
// 入站是 TLS+H2 over TCP,由运行时的 TCP 接入环托管监听(NewHandler 形态)。
//
// 出站字段:server / user / secret(或 password)/ sni / insecure / client-fingerprint。
// 入站用户 = Basic 名 + 口令(顶层 users 写 keys.naive,Basic 名 = 计量 tag;口内 users 写 name/password);
// 服务端 TLS 由运行时从 tls: 块加载。
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "naive",
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
		Server:      n.Get("server").Str(),
		User:        n.Get("user").Str(),
		Password:    pw,
		SNI:         n.Get("sni").Str(),
		Insecure:    n.Get("insecure").Bool(),
		Fingerprint: n.Get("client-fingerprint").Str(),
	})
}

func newHandlerFromSession(in registry.SessionInbound) (endpoint.InboundHandler, error) {
	users := make([]User, 0, len(in.Users))
	for _, u := range in.Users {
		if u.Tag == "" {
			continue
		}
		pw := u.Fields["password"]
		if pw == "" {
			pw = u.Secret
		}
		users = append(users, User{Name: u.Tag, Password: pw}) // Basic 名 = tag,与计量回读表键一致
	}
	if len(users) == 0 {
		return nil, errors.New("naive 入站需至少一个用户(顶层 users.keys.naive{password} 或口内 user{name,password})")
	}
	tlsConf, err := in.ServerTLS()
	if err != nil {
		return nil, err
	}
	return NewInbound(users, tlsConf, in.Out, in.Dispatch)
}
