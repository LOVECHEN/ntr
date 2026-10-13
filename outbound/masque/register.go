package masque

import (
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/internal/selfcert"
)

// 会话式协议插件自注册(registry.RegisterSession):运行时按 type: masque 查表,本包自解字段。
// 入站跑在 QUIC + HTTP/3 上(connect-udp RFC 9298 + CONNECT RFC 9220),自管监听(NewInbound → Runner)。
//
// 出站字段:server / sni / insecure / user + secret(或 password)(可选 HTTP Basic)。
// 入站用户可为空 = 不鉴权(MASQUE 无标准认证层,身份落 Ambient);有则 Basic 名 = 计量 tag(顶层 users 写
// keys.masque 口令;口内 users 写 name/password)。服务端 TLS 用 tls: 块 cert/key(metacubex TLS,未配则自签)。
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "masque",
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
		User:     n.Get("user").Str(),
		Password: pw,
		SNI:      n.Get("sni").Str(),
		Insecure: n.Get("insecure").Bool(),
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
		users = append(users, User{Name: u.Tag, Password: pw}) // Basic 名 = tag,与计量回读表键一致
	}
	tlsConf, err := selfcert.Metacubex(in.TLSCert, in.TLSKey)
	if err != nil {
		return nil, err
	}
	return NewInbound(users, tlsConf, in.Out, in.Dispatch, in.PacketDispatch)
}
