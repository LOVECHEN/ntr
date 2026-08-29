package snell

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv123"
	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv45"
	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv6"
)

// ServerHandshake 实现 proxy.Server:用端口 PSK 跑 Snell v6 握手,返回承载中继 payload 的
// stream + Request(dst + 归属凭据 + 命令)。
//
// 认证靠端口 PSK(单 PSK,O(1),不试 Argon2id);用户身份靠命令里的 clientID → CredID
// (经 auth)。未知 clientID → Ambient(端口 PSK 已鉴权、用户身份未登记)。
func (p *Proxy) ServerHandshake(_ context.Context, below link.Stream, auth proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	// 归一化握手结果(v4/v5 与 v6 的 AcceptResult 字段一致,在此收敛)。
	var (
		relay    net.Conn
		command  byte
		clientID string
		host     string
		port     uint16
		v6res    *snellv6.AcceptResult   // 保留 v6 结果供 UDP 适配(取 ServerPacketConn)
		v45res   *snellv45.AcceptResult  // 同上,v4/v5
		v123res  *snellv123.AcceptResult // 同上,v3(v1/v2 无 UDP)
	)
	if p.isV123() {
		res, err := (&snellv123.Server{PSK: p.cfg.PSK, ChaCha: p.v123ChaCha()}).Accept(below)
		if err != nil {
			return nil, nil, err
		}
		v123res = res
		relay, command, clientID, host, port = res.Conn, res.Command, res.ClientID, res.Host, res.Port
	} else if p.isV45() {
		res, err := (&snellv45.Server{PSK: p.cfg.PSK}).Accept(below)
		if err != nil {
			return nil, nil, err
		}
		v45res = res
		relay, command, clientID, host, port = res.Conn, res.Command, res.ClientID, res.Host, res.Port
	} else {
		res, err := (&snellv6.Server{PSK: p.cfg.PSK, Mode: p.cfg.Mode}).Accept(below)
		if err != nil {
			return nil, nil, err
		}
		v6res = res
		relay, command, clientID, host, port = res.Conn, res.Command, res.ClientID, res.Host, res.Port
		if len(res.Initial) > 0 {
			// v6 客户端把 CONNECT 与目标首段数据合并进同一 AEAD chunk(省 RTT);res.Initial 是命令后
			// 已从流里解出的这段数据。必须前置到 relay 读流,否则 target 收到的首批字节缺失(HTTP 请求
			// 行/TLS ClientHello 残缺,连接损坏)。v4/v5 走 serverConn.rbuf seed 已保留,唯 v6 需在此补。
			relay = &prefixReadConn{Conn: relay, prefix: res.Initial}
		}
	}

	ref := cred.Ref{ID: cred.Ambient}
	if r, ok := auth.Auth("snell", []byte(clientID)); ok {
		ref = r
	}

	// UDP(CmdUDP):返回载两代引擎之一的 ServerPacketConn 的 carrier,交 ServerPacketConn→udpNAT 多目标落地。
	if command == snellv6.CmdUDP {
		var spc udpServerSession
		var ok bool
		switch {
		case v123res != nil: // v3(v1/v2 无 UDP;命令层已在 parseCommand 放行 cmd6)
			spc, ok = v123res.AsServerPacketConn()
		case v45res != nil:
			spc, ok = v45res.AsServerPacketConn()
		default:
			spc, ok = v6res.AsServerPacketConn()
		}
		if !ok {
			return nil, nil, errors.New("snell: UDP 适配失败(非预期 serverConn)")
		}
		return &udpCarrier{Stream: below, pc: spc},
			&proxy.Request{Cred: ref, Network: endpoint.NetworkUDP, Command: command}, nil
	}

	// TCP(CONNECT / CONNECT-Reuse):承载 payload 的 stream。
	req := &proxy.Request{Cred: ref, Network: endpoint.NetworkTCP, Command: command}
	if command == snellv6.CmdConnect || command == snellv6.CmdConnectReuse {
		req.Dst = hostToSocksaddr(host, port)
	}
	return &streamWrap{Conn: relay, below: below}, req, nil
}

// prefixReadConn 在 relay 读流前置一段已解出的初始数据(snell v6 piggyback),读完后透传底层。
type prefixReadConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixReadConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// hostToSocksaddr 把 snell 命令里的 host(可能是 IP 字面量或域名)归一成 Socksaddr。
func hostToSocksaddr(host string, port uint16) addr.Socksaddr {
	if ip, err := netip.ParseAddr(host); err == nil {
		return addr.FromIPPort(netip.AddrPortFrom(ip, port))
	}
	return addr.FromFqdn(host, port)
}
