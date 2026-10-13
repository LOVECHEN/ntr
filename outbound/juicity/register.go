package juicity

import (
	"fmt"
	"strings"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// 会话式协议插件自注册:运行时按 type: juicity 查表,本包自解字段。
//
// 出站(sni 缺省取 server 主机名;alpn 缺省 h3;congestion-control 缺省 bbr,可选 cubic):
//
//	outbounds:
//	  - name: j
//	    type: juicity
//	    server: example.com:443
//	    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
//	    secret: password-here
//	    sni: example.com
//	    insecure: false
//	    alpn:
//	      - h3
//	    congestion-control: bbr
//
// 入站(用户 = 复合键 uuid + password;顶层 users 写 keys.juicity 的 uuid/password,口内 users 同名字段):
//
//	inbounds:
//	  - name: j-in
//	    type: juicity
//	    listen: 0.0.0.0:443
//	    tls:
//	      cert-file: /path/cert.pem
//	      key-file: /path/key.pem
//	    users:
//	      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
//	        password: password-here
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "juicity",
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
		ALPN:              strList(n.Get("alpn")),
		CongestionControl: n.Get("congestion-control").Str(),
	})
}

func newInboundFromSession(in registry.SessionInbound) (registry.Runner, error) {
	users := make([]User, 0, len(in.Users))
	for _, u := range in.Users {
		id := u.Fields["uuid"]
		if id == "" {
			return nil, fmt.Errorf("juicity: 用户 %q 缺 uuid(juicity 是复合键 uuid + password)", u.Tag)
		}
		pw := u.Fields["password"]
		if pw == "" {
			pw = u.Secret
		}
		users = append(users, User{Name: u.Tag, UUID: id, Password: pw})
	}
	return NewInbound(InboundOptions{
		Users:          users,
		TLS:            in.TLS,
		Out:            in.Out,
		Dispatch:       in.Dispatch,
		Admit:          in.Admit,
		PacketDispatch: in.PacketDispatch,
	})
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
