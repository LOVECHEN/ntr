package mieru

import (
	"errors"
	"fmt"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// 会话式协议插件自注册(registry.RegisterSession):运行时按 type: mieru 查表,本包自解字段。
// 入站用官方库自绑端口(NewInbound → Runner)。
//
// 出站字段:server / transport(TCP|UDP,默认 TCP)/ user / secret(或 password)/ multiplexing。
// 入站:transport;用户 = 名 + 口令,★库内认证用户名 = 计量 tag(UserName() 回读的正是它,须与回读表键一致),
// 故顶层 users 的 keys.mieru 只写口令(标量或 {password});口内 users 写 name/password。
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "mieru",
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
		Server:       n.Get("server").Str(),
		Transport:    n.Get("transport").Str(),
		Username:     n.Get("user").Str(),
		Password:     pw,
		Multiplexing: n.Get("multiplexing").Str(),
	})
}

func newInboundFromSession(in registry.SessionInbound) (registry.Runner, error) {
	users := make([]User, 0, len(in.Users))
	for _, u := range in.Users {
		if u.Tag == "" {
			continue
		}
		pw := u.Fields["password"]
		if pw == "" {
			pw = u.Secret
		}
		if pw == "" {
			return nil, fmt.Errorf("mieru: 用户 %q 缺口令(顶层 users 写 keys.mieru,口内 users 写 password)", u.Tag)
		}
		users = append(users, User{Name: u.Tag, Password: pw})
	}
	if len(users) == 0 {
		return nil, errors.New("mieru 入站需至少一个用户(顶层 users.keys.mieru{password} 或口内 user{name,password})")
	}
	return NewInbound(users, in.Node.Get("transport").Str(), in.Out, in.Dispatch, in.PacketDispatch)
}
