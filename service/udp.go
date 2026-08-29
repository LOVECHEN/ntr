package service

import (
	"context"
	"fmt"
	"net"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// ServePacket 在一个 UDP socket 上跑【原生 datagram 入站】(Shadowsocks 等,不 over stream)。
// 交给协议的 PacketServer 能力解密/解目标,对每条逻辑 UDP 流经核心 udpNAT 落地到出站。
// 阻塞至 ctx 取消或 socket 关闭。协议无该能力则大声报(不静默)。
//
// ★ 与 TCP 路径正交:native UDP 不经 h.Below 传输链(原生 UDP 协议自身即自包含加密,
// 其上不叠 stream 传输)。故这里直接把裸 socket 交协议,核心只负责 udpNAT 落地。
func (h *ProxyInbound) ServePacket(ctx context.Context, pc net.PacketConn) error {
	ps, ok := h.Proxy.(proxy.PacketServer)
	if !ok {
		return fmt.Errorf("service: 协议不支持原生 UDP 入站(无 PacketServer 能力)")
	}
	// sink:协议每解出一条逻辑 UDP 流就调一次。★必须【同步阻塞】跑 udpNAT —— sink 由协议在其
	// 每源会话 goroutine 内调用(sing 的 handler.NewPacketConnection 就在独立 goroutine 里),
	// 且协议会在 sink 返回后立刻关掉这条 clientPC(sing udpnat 的生命周期契约)。若这里改 go 起,
	// clientPC 会被立刻关闭、udpNAT 的 ReadPacket 秒错退出。故同步跑;clientPC 的关闭交给协议侧。
	sink := func(clientPC link.PacketConn) {
		_ = udpNAT(ctx, clientPC, h.Out)
	}
	return ps.ServePacket(ctx, pc, sink)
}

// SupportsNativePacket 报告本入站的顶层协议是否具备原生 UDP 入站能力(供 cmd 决定是否另开 UDP 监听)。
func (h *ProxyInbound) SupportsNativePacket() bool {
	_, ok := h.Proxy.(proxy.PacketServer)
	return ok
}
