package trusttunnel

import (
	"errors"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/internal/selfcert"
)

// 会话式协议插件自注册(registry.RegisterSession):运行时按 type: trusttunnel 查表,本包自解字段。
// 入站是 TLS+H2 over TCP,由运行时的 TCP 接入环托管监听(NewHandler 形态)。
//
// 出站字段:server / user / secret(或 password)/ sni / insecure / client-fingerprint / quic(走 HTTP/3)。
// 入站用户 = Basic 名 + 口令(顶层 users 写 keys.trusttunnel,Basic 名 = 计量 tag;口内 users 写 name/password);
// 服务端 TLS 由运行时从 tls: 块加载;quic: true 时同端口另开 UDP 跑 HTTP/3。
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "trusttunnel",
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
		QUIC:        n.Get("quic").Bool(),
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
		return nil, errors.New("trusttunnel 入站需至少一个用户(顶层 users.keys.trusttunnel{password} 或口内 user{name,password})")
	}
	tlsConf, err := in.ServerTLS()
	if err != nil {
		return nil, err
	}
	inb, err := NewInbound(users, tlsConf, in.Out, in.Dispatch, in.PacketDispatch)
	if err != nil {
		return nil, err
	}
	if in.Node.Get("quic").Bool() { // quic: true → 同端口另开 UDP 跑 HTTP/3(证书与 H2 同一张)
		h3TLS, err := selfcert.Metacubex(in.TLSCert, in.TLSKey)
		if err != nil {
			return nil, err
		}
		inb.EnableH3(h3TLS)
	}
	return inb, nil
}
