package hysteria2

import (
	"errors"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// 会话式协议插件自注册(registry.RegisterSession):运行时按 type: hysteria2 查表,本包自解字段。
// 入站跑在 QUIC(UDP)上,自管监听(NewInbound → Runner)。
//
// 出站字段:server / secret(或 password)/ sni / insecure / obfs(salamander 口令)。
// 入站:obfs(salamander 口令);用户 = 标量口令(顶层 users 写 keys.hysteria2,口内 users 写 password);
// 服务端 TLS 用 tls: 块的 cert/key(metacubex TLS,未配则临时自签)。
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "hysteria2",
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
		Password: pw,
		SNI:      n.Get("sni").Str(),
		Insecure: n.Get("insecure").Bool(),
		Obfs:     n.Get("obfs").Str(),
	})
}

func newInboundFromSession(in registry.SessionInbound) (registry.Runner, error) {
	users := make([]User, 0, len(in.Users))
	for _, u := range in.Users {
		pw := u.Secret
		if pw == "" {
			pw = u.Fields["password"]
		}
		if pw == "" {
			continue
		}
		users = append(users, User{Name: u.Tag, Password: pw})
	}
	if len(users) == 0 {
		return nil, errors.New("hysteria2 入站需至少一个用户(顶层 users.keys.hysteria2 或口内 user{password})")
	}
	tlsConf, err := ServerTLSConfig(in.TLSCert, in.TLSKey)
	if err != nil {
		return nil, err
	}
	return NewInbound(users, tlsConf, in.Node.Get("obfs").Str(), in.Out, in.Dispatch, in.PacketDispatch)
}
