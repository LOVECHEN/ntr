package service

import (
	"context"
	"errors"
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
		c, err := n.conn(dst)
		if err != nil {
			continue // 单个目标建连/超限失败不拖垮整条关联(其余目标继续)
		}
		if err := c.WritePacket(b, dst); err != nil {
			continue
		}
	}
}

type udpNat struct {
	ctx      context.Context
	client   link.PacketConn
	resolver OutboundResolver
	mu       sync.Mutex               // 护 conns
	conns    map[string]link.PacketConn
	writeMu  sync.Mutex // 串行化对 client 的反向写(多个反向 goroutine 共用一条 client,整帧不得交错)
}

// conn 取/建 dst 对应的单目标出站(仅 forward 单 goroutine 调用),首建时起反向 goroutine。
func (n *udpNat) conn(dst addr.Socksaddr) (link.PacketConn, error) {
	key := dst.String()
	n.mu.Lock()
	if c, ok := n.conns[key]; ok {
		n.mu.Unlock()
		return c, nil
	}
	if len(n.conns) >= maxUDPTargets {
		n.mu.Unlock()
		return nil, errTooManyTargets
	}
	n.mu.Unlock()

	out, err := n.resolver.Resolve(n.ctx, dst)
	if err != nil {
		return nil, err
	}
	c, err := out.DialPacket(n.ctx, dst)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.conns[key] = c
	n.mu.Unlock()
	go n.reverse(dst, c)
	return c, nil
}

// reverse 读某目标的响应,回写 client(dst=该响应来源目标,让多目标客户端知道是谁回的)。
func (n *udpNat) reverse(dst addr.Socksaddr, c link.PacketConn) {
	b := buf.New()
	defer b.Release()
	for {
		b.Reset()
		if _, err := c.ReadPacket(b); err != nil {
			return
		}
		n.writeMu.Lock()
		err := n.client.WritePacket(b, dst)
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
	n.mu.Unlock()
}
