package anytls

import (
	"errors"
	"fmt"
	"strings"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// 会话式协议插件自注册(registry.RegisterSession):运行时按 type: anytls 查表,本包自解字段。
// 入站是 TLS-over-TCP,由运行时的 TCP 接入环托管监听(NewHandler 形态)。
//
// 出站字段:server / secret(或 password)/ sni / insecure / alpn。
// 入站用户 = 标量口令(顶层 users 写 keys.anytls,口内 users 写 password);服务端 TLS 由运行时从 tls: 块加载。
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "anytls",
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
		Server:   n.Get("server").Str(),
		Password: pw,
		SNI:      n.Get("sni").Str(),
		Insecure: n.Get("insecure").Bool(),
		ALPN:     strList(n.Get("alpn")),
	})
}

func newHandlerFromSession(in registry.SessionInbound) (endpoint.InboundHandler, error) {
	users := make([]User, 0, len(in.Users))
	for _, u := range in.Users {
		pw := u.Secret
		if pw == "" {
			pw = u.Fields["password"]
		}
		if pw == "" {
			return nil, fmt.Errorf("anytls: 用户 %q 缺口令(顶层 users 写 keys.anytls,口内 users 写 password)", u.Tag)
		}
		users = append(users, User{Name: u.Tag, Password: pw})
	}
	if len(users) == 0 {
		return nil, errors.New("anytls 入站需至少一个用户(顶层 users.keys.anytls 或口内 user{password})")
	}
	tlsConf, err := in.ServerTLS()
	if err != nil {
		return nil, err
	}
	return NewInbound(users, tlsConf, in.Out, in.Dispatch)
}

// strList 读字符串列表:序列节点逐项取,标量按逗号拆。
func strList(n *spec.Node) []string {
	if n == nil {
		return nil
	}
	var out []string
	if n.Kind == spec.KindSeq {
		for _, s := range n.Seq {
			if v := strings.TrimSpace(s.Str()); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	for _, v := range strings.Split(n.Str(), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
