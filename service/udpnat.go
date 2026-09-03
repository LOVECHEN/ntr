package service

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

// errTooManyTargets:单条 UDP 关联同时打开的不同目标超上限(防恶意客户端拿海量目标撑爆 socket)。
var errTooManyTargets = errors.New("service: UDP 关联目标数超上限")

// maxUDPTargets 单条关联的不同目标上限。
const maxUDPTargets = 512

// udpNAT 把一条(可能多目标的)客户端 PacketConn 分发到按 per-packet dst 建的多条单目标出站
// datagram 连接(承 direct.go 注释:多目标 = 上游 udpnat 拆成多条单目标 assoc)。
//
// 对单目标协议(VLESS:每包 dst 恒为握手目标)退化成"一个目标一条出站",行为不变;对多目标协议
// (Trojan:每包自带地址)则每见一个新目标就开一条出站。生命周期绑定客户端 conn:client 一关,
// forward 循环返回、defer 关掉所有出站 → 各反向 goroutine 的 ReadPacket 出错自然收尾,不泄漏。
func udpNAT(ctx context.Context, client link.PacketConn, resolver OutboundResolver) error {
	n := &udpNat{ctx: ctx, client: client, resolver: resolver, conns: make(map[string]link.PacketConn)}
	defer n.closeAll()

	b := buf.New()
	defer b.Release()
	for {
		b.Reset()
		dst, err := client.ReadPacket(b)
		if err != nil {
			return err
		}
		// 首包嗅探(protocol 规则):对【新目标】识别应用协议(当前 STUN)→ 供路由按 protocol 拦截
		// (如 WebRTC srflx 的 STUN 探测,不靠端口/域名)。已建目标沿用其首次路由,不再重嗅。
		proto := ""
		if !n.known(dst) {
			proto = sniffPacket(b.Bytes()).String()
		}
		c, err := n.conn(dst, proto)
		if err != nil {
			continue // 单个目标建连/超限失败(含被 protocol 规则路由到 block)不拖垮整条关联(其余目标继续)
		}
		if err := c.WritePacket(b, dst); err != nil {
			continue
		}
	}
}

// known 报告 dst 是否已建出站(full-cone 下全会话共享,任意目标即已知)。
func (n *udpNat) known(dst addr.Socksaddr) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.shared != nil {
		return true
	}
	_, ok := n.conns[dst.String()]
	return ok
}

type udpNat struct {
	ctx      context.Context
	client   link.PacketConn
	resolver OutboundResolver
	mu       sync.Mutex // 护 conns/shared
	conns    map[string]link.PacketConn
	shared   link.PacketConn // full-cone 出站:全会话共享的单 unconnected socket(非 per-target)
	writeMu  sync.Mutex      // 串行化对 client 的反向写(多个反向 goroutine 共用一条 client,整帧不得交错)
}

// conn 取/建 dst 对应的单目标出站(仅 forward 单 goroutine 调用),首建时起反向 goroutine。
// proto 是首包嗅探出的应用协议(供 protocol 规则;仅新目标首建时非空)。
func (n *udpNat) conn(dst addr.Socksaddr, proto string) (link.PacketConn, error) {
	key := dst.String()
	n.mu.Lock()
	if n.shared != nil { // full-cone:全会话一个 socket,任意目标复用
		c := n.shared
		n.mu.Unlock()
		return c, nil
	}
	if c, ok := n.conns[key]; ok {
		n.mu.Unlock()
		return c, nil
	}
	if len(n.conns) >= maxUDPTargets {
		n.mu.Unlock()
		return nil, errTooManyTargets
	}
	n.mu.Unlock()

	// UDP 路由:带 network="udp"(供 network 维度规则)+ 嗅探 proto(供 protocol 规则,如 stun→block),
	// 源暂不反查进程(UDP process 规则后续)。
	out, err := resolveOut(withSniffedProto(n.ctx, proto), n.resolver, dst, netip.AddrPort{}, "udp")
	if err != nil {
		return nil, err
	}
	c, err := out.DialPacket(n.ctx, dst)
	if err != nil {
		return nil, err
	}
	// full-cone 出站(unconnected 单端口):记为共享,全会话多目标复用它;反向 goroutine 用【真实来源】回写 client。
	if _, ok := c.(interface{ FullCone() }); ok {
		n.mu.Lock()
		n.shared = c
		n.mu.Unlock()
		go n.reverse(dst, c)
		return c, nil
	}
	n.mu.Lock()
	n.conns[key] = c
	n.mu.Unlock()
	go n.reverse(dst, c)
	return c, nil
}

// reverse 读某出站的响应,回写 client。回写目标用 ReadPacket 返回的【来源】:per-target(connected)恒返回其 dst;
// full-cone(unconnected 共享 socket)返回真实来源 —— 让多目标客户端知道是谁回的(endpoint-independent 也正确)。
func (n *udpNat) reverse(fallback addr.Socksaddr, c link.PacketConn) {
	b := buf.New()
	defer b.Release()
	for {
		b.Reset()
		src, err := c.ReadPacket(b)
		if err != nil {
			return
		}
		if !src.IsValid() {
			src = fallback
		}
		n.writeMu.Lock()
		err = n.client.WritePacket(b, src)
		n.writeMu.Unlock()
		if err != nil {
			return
		}
	}
}

func (n *udpNat) closeAll() {
	n.mu.Lock()
	for _, c := range n.conns {
		_ = c.Close()
	}
	if n.shared != nil {
		_ = n.shared.Close()
	}
	n.mu.Unlock()
}
