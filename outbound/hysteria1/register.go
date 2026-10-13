package hysteria1

import (
	"errors"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// 会话式协议插件自注册(registry.RegisterSession):运行时按 type: hysteria1 查表,本包自解字段。
// 入站跑在 QUIC(UDP)上,自管监听(NewInbound → Runner)。
//
// 出站字段:server / secret(或 password)/ sni / insecure / obfs(混淆口令)。
// 入站:obfs;用户 = 标量口令(顶层 users 写 keys.hysteria1,口内 users 写 password);服务端 TLS 由运行时
// 从 tls: 块加载。TCP 流走 Admit(落地前须回 hy1 握手信令,协议自管 relay);反连 portal 口运行时不给
// Admit,流经 Dispatch 改派进隧道。
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "hysteria1",
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
		Obfs:     n.Get("obfs").Str(),
		SNI:      n.Get("sni").Str(),
		Insecure: n.Get("insecure").Bool(),
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
		return nil, errors.New("hysteria1 入站需至少一个用户(顶层 users.keys.hysteria1 或口内 user{password})")
	}
	tlsConf, err := in.ServerTLS()
	if err != nil {
		return nil, err
	}
	return NewInbound(users, in.Node.Get("obfs").Str(), 0, 0, tlsConf, in.Out, in.Dispatch, in.Admit, in.PacketDispatch)
}
