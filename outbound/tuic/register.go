package tuic

import (
	"errors"
	"fmt"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// 会话式协议插件自注册(registry.RegisterSession):运行时按 type: tuic 查表,本包自解字段。
//
// 出站字段:server / uuid / secret(或 password)/ sni / insecure / congestion-control。
// 入站用户 = 复合键 uuid + password(顶层 users 写 keys.tuic 的 uuid/password,口内 users 同名字段);
// 服务端 TLS 由运行时从 tls: 块加载(未配则临时自签)。
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "tuic",
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
		Server:            n.Get("server").Str(),
		UUID:              n.Get("uuid").Str(),
		Password:          pw,
		SNI:               n.Get("sni").Str(),
		Insecure:          n.Get("insecure").Bool(),
		CongestionControl: n.Get("congestion-control").Str(),
	})
}

func newInboundFromSession(in registry.SessionInbound) (registry.Runner, error) {
	users := make([]User, 0, len(in.Users))
	for _, u := range in.Users {
		id := u.Fields["uuid"]
		if id == "" {
			return nil, fmt.Errorf("tuic: 用户 %q 缺 uuid(tuic 是复合键 uuid + password,顶层 users 须写结构化 keys.tuic{uuid,password})", u.Tag)
		}
		pw := u.Fields["password"]
		if pw == "" {
			pw = u.Secret
		}
		users = append(users, User{Name: u.Tag, UUID: id, Password: pw})
	}
	if len(users) == 0 {
		return nil, errors.New("tuic 入站需至少一个用户(顶层 users.keys.tuic{uuid,password} 或口内 user{uuid,password})")
	}
	tlsConf, err := in.ServerTLS()
	if err != nil {
		return nil, err
	}
	return NewInbound(users, tlsConf, in.Out, in.Dispatch)
}
