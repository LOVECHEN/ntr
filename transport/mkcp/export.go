package mkcp

import (
	"context"
	"net"

	"github.com/LOVECHEN/ntr/transport/mkcp/internal/mkcpcore"
)

// KCPParams 是 mKCP 参数,供【本仓其它传输】(如 mekya)在任意载体上跑与 mihomo/xray 线级互通的 KCP。
// 因 mkcpcore 是 internal 包,外部传输不能直接引用;经本公开 API 转发,避免内部类型泄漏。
type KCPParams struct {
	MTU              uint32
	TTI              uint32
	UplinkCapacity   uint32
	DownlinkCapacity uint32
	Congestion       bool
	WriteBuffer      uint32
	ReadBuffer       uint32
	Seed             string
	Header           string
}

func (p KCPParams) core() mkcpcore.Config {
	return mkcpcore.Config{
		MTU: p.MTU, TTI: p.TTI, UplinkCapacity: p.UplinkCapacity, DownlinkCapacity: p.DownlinkCapacity,
		Congestion: p.Congestion, WriteBuffer: p.WriteBuffer, ReadBuffer: p.ReadBuffer,
		Seed: p.Seed, Header: p.Header,
	}
}

// KCPListener 是 KCP 监听器的公开接口(mkcpcore.Listener 满足之)。
type KCPListener interface {
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

// DialKCP 在任意 net.Conn(数据报语义:每 Read/Write 一个 KCP 包)上跑 KCP 客户端会话。
func DialKCP(ctx context.Context, raw net.Conn, p KCPParams) (net.Conn, error) {
	return mkcpcore.Dial(ctx, raw, p.core())
}

// ListenKCP 在任意 net.PacketConn 上跑 KCP 监听(按 addr 区分会话)。
func ListenKCP(ctx context.Context, pc net.PacketConn, p KCPParams) (KCPListener, error) {
	return mkcpcore.Listen(ctx, pc, p.core())
}
