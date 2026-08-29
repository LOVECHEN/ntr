// Package upstream 是"转发到上游代理服务器"的出站:拨上游 TCP → 自底向上过客户端
// 传输链(ClientWrap)→ 用 proxy.Client 握手把逻辑目标交给上游。
//
// 它是 service.ProxyInbound 的镜像(出站方向):同一套 transport + proxy 插件,方向相反。
// 链式部署(ntr-client → ntr-server → direct)据此成立,且对协议/传输零特判。
package upstream

import (
	"context"
	"errors"
	"net"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/transport"
)

var _ endpoint.Outbound = (*Outbound)(nil)

// Outbound 拨到 Server(上游代理),经 Below 传输链 + Client 协议握手承载 dst。
type Outbound struct {
	Server string                      // 上游 host:port
	Dialer net.Dialer                  // 底层拨号策略(超时/本地地址/Control)
	Below  []transport.StreamTransport // 底→顶客户端传输链(如 [tls])
	Client proxy.Client                // 顶层协议客户端
	Key    []byte                      // 本机出示给上游的凭据(uuid/password/psk)
	// BaseDial 非 nil 时替代默认 TCP 拨号(mkcp 等 UDP-base 传输:自建 UDP+KCP 底层可靠流)。
	BaseDial func(ctx context.Context, server string) (link.Stream, error)
}

// dialBase 建立底层 base 流:有 BaseDial(mkcp 等)走它,否则默认拨 TCP。
func (o *Outbound) dialBase(ctx context.Context) (link.Stream, error) {
	if o.BaseDial != nil {
		return o.BaseDial(ctx, o.Server)
	}
	raw, err := o.Dialer.DialContext(ctx, "tcp", o.Server)
	if err != nil {
		return nil, err
	}
	return connStream{raw}, nil
}

// DialStream 建立到上游、承载 dst 的一条流。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	below, err := o.dialBase(ctx) // 默认 TCP;mkcp 等走 BaseDial(UDP+KCP)
	if err != nil {
		return nil, err
	}
	base := below
	for _, t := range o.Below { // 底→顶:base →(tls)→ 给协议客户端的下层
		wrapped, err := t.ClientWrap(ctx, below)
		if err != nil {
			_ = base.Close()
			return nil, err
		}
		below = wrapped
	}
	s, err := o.Client.ClientHandshake(ctx, below, o.Key, dst)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	return s, nil
}

// DialPacket 经上游承载 UDP:另拨一条到上游的连接 + 传输链,由协议客户端的 UDP 能力
// (PacketConnClient)发起单目标关联。协议不支持 UDP-over-stream 则大声报。
func (o *Outbound) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	// 原生 UDP 协议(Shadowsocks 等)优先:自建 UDP socket,不拨无用 TCP below。
	if npc, ok := o.Client.(proxy.NativePacketConnClient); ok {
		return npc.DialNativePacketConn(ctx, o.Server, o.Key, dst)
	}
	pcc, ok := o.Client.(proxy.PacketConnClient)
	if !ok {
		return nil, errors.New("upstream: 上游协议不支持 UDP(既无 NativePacketConnClient 也无 PacketConnClient 能力)")
	}
	below, err := o.dialBase(ctx) // 默认 TCP;mkcp 等走 BaseDial
	if err != nil {
		return nil, err
	}
	base := below
	for _, t := range o.Below {
		wrapped, err := t.ClientWrap(ctx, below)
		if err != nil {
			_ = base.Close()
			return nil, err
		}
		below = wrapped
	}
	pc, err := pcc.DialPacketConn(ctx, below, o.Key, dst)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	return pc, nil
}

// connStream 把裸 net.Conn 抬成 link.Stream(链底,Unwrap 到底层供能力发现)。
type connStream struct{ net.Conn }

func (c connStream) Unwrap() any { return c.Conn }
