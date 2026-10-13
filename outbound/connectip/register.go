package connectip

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/internal/selfcert"
)

// 会话式协议插件自注册(registry.RegisterSession):运行时按 type: connect-ip 查表,本包自解字段。
// 两种构建下都注册:未编入(-tags with_connectip 缺省)时 NewOutbound/NewInbound 由桩返回 ErrNotBuilt,
// 配了 connect-ip 就明确报错,不静默降级。入站自管 QUIC/h3 监听(NewInbound → Runner)。
//
// 出站字段:server / sni / insecure / protocol / uri-template / ignore-extended-connect / local-address /
// dns / mtu / client-cert / client-key / preset(cloudflare = 套用 WARP 的三处非标差异,显式字段仍可覆盖)。
// 入站:assign-address / mtu;用户可空 = 开放隧道(RFC 9484 无认证层,与 Cloudflare 等无认证客户端互通),
// 有则 Basic 名 = 计量 tag。整条隧道经运行时 AdmitTunnel 一次接入、按 IP 包字节记账;不能当反连 portal。
func init() {
	registry.RegisterSession(registry.Session{
		Name:            "connect-ip",
		NewOutbound:     newOutboundFromNode,
		NewInbound:      newInboundFromSession,
		UserFromContext: UserFromContext,
	})
}

func newOutboundFromNode(n *spec.Node) (endpoint.Outbound, error) {
	o := Options{
		Server:                n.Get("server").Str(),
		SNI:                   n.Get("sni").Str(),
		Insecure:              n.Get("insecure").Bool(),
		Protocol:              n.Get("protocol").Str(),
		URITemplate:           n.Get("uri-template").Str(),
		IgnoreExtendedConnect: n.Get("ignore-extended-connect").Bool(),
		LocalAddress:          strList(n.Get("local-address")),
		DNS:                   strList(n.Get("dns")),
		MTU:                   n.Get("mtu").Int(0),
		ClientCert:            n.Get("client-cert").Str(),
		ClientKey:             n.Get("client-key").Str(),
	}
	// preset=cloudflare 依据 mihomo transport/masque/masque.go:protocol 用 cf-connect-ip、发已废弃的
	// SETTINGS_H3_DATAGRAM_00(0x276)、跳过 Extended CONNECT 校验。
	if n.Get("preset").Str() == "cloudflare" {
		if o.Protocol == "" {
			o.Protocol = "cf-connect-ip"
		}
		o.ExtraSettings = map[uint64]uint64{0x276: 1}
		o.IgnoreExtendedConnect = true
	}
	return NewOutbound(o)
}

func newInboundFromSession(in registry.SessionInbound) (registry.Runner, error) {
	if in.AdmitTunnel == nil {
		return nil, errors.New("connect-ip 是整包 L3 隧道,不能当反连 portal(无法逐流改派)")
	}
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
	admit := in.AdmitTunnel
	hook := func(ctx context.Context, user string, src net.Addr, closer io.Closer) (func(int), func(int), func(), bool) {
		return admit(withUser(ctx, user), src, closer)
	}
	return NewInbound(InboundOptions{
		AssignAddress: in.Node.Get("assign-address").Str(),
		MTU:           in.Node.Get("mtu").Int(0),
	}, users, hook, tlsConf, in.Out)
}

// strList 读字符串列表:序列节点逐项取,标量单值。
func strList(n *spec.Node) []string {
	if n == nil {
		return nil
	}
	if n.Kind == spec.KindSeq {
		out := make([]string, 0, len(n.Seq))
		for _, s := range n.Seq {
			if v := s.Str(); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	if v := n.Str(); v != "" {
		return []string{v}
	}
	return nil
}
