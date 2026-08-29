package vmess

import (
	"context"
	"errors"
	"net"
	"time"

	vmess "github.com/metacubex/sing-vmess"
	singbuf "github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// VMess 也实现 UDP-over-stream。复用第三方 sing-vmess 的 PacketConn:统一走 sing 帧对齐的
// ReadPacket/WritePacket(buf.Buffer)API —— 与 sing-box / mihomo 消费 sing 的方式一致,能同时
// 兼容【普通 Command=UDP】(sing/mihomo 客户端)与【XUDP/Mux】(xray 客户端默认)两种线上封装。
// 单目标:读出的 dst 恒握手目标;写回携带 udpNAT 传入的真实回程 dst(XUDP 每包自带地址,必须写对)。
var (
	_ proxy.PacketConnServer = (*Proxy)(nil)
	_ proxy.PacketConnClient = (*Proxy)(nil)
)

// writeFrontHeadroom 是写缓冲预留的前置头空间:够 XUDP 每包头(9 + 最长 socks 地址)。sing 的
// serverMuxPacketConn.WritePacket 用 ExtendHeader 就地前插该头;普通 AEAD writer 前插 2B 长度也够用。
const writeFrontHeadroom = 9 + M.MaxSocksaddrLength

// writeRearHeadroom 是写缓冲预留的【后置】尾空间。sing 的 AEAD writer 就地封装:
// AEADWriter.WriteBuffer 会 buffer.Extend(CipherOverhead) 把 16B poly1305 tag 追加到尾部;
// 开 GlobalPadding 时还会追加最多 MaxPaddingSize 的随机填充。缓冲必须留够尾空间,否则 Extend
// 溢出 panic(实测「buffer overflow: capacity/end 相等, need 16」)。取 sing-vmess 声明的
// MaxRearHeadroom(=CipherOverhead*2 + MaxPaddingSize),与其 rawClientConn/rawServerConn 的
// RearHeadroom() 契约一致 —— 覆盖客户端(DialPacketConn)与服务端回程(ServerPacketConn)两条写路径。
const writeRearHeadroom = vmess.MaxRearHeadroom

// DialPacketConn 实现 proxy.PacketConnClient:发起 VMess UDP 会话,返回桥接的 link.PacketConn。
func (p *Proxy) DialPacketConn(_ context.Context, below link.Stream, _ []byte, dst addr.Socksaddr) (link.PacketConn, error) {
	sc, err := p.client.DialPacketConn(below, toSing(dst))
	if err != nil {
		return nil, err
	}
	return &packetConn{pc: sc, dst: dst, below: below}, nil
}

// ServerPacketConn 实现 proxy.PacketConnServer:从 UDP 握手捕获的 packetCarrier 取出 sing
// PacketConn(普通 serverPacketConn 或 XUDP 的 serverMuxPacketConn),适配成 link.PacketConn。
func (p *Proxy) ServerPacketConn(hs link.Stream, dst addr.Socksaddr) (link.PacketConn, error) {
	pc, ok := hs.(*packetCarrier)
	if !ok {
		return nil, errors.New("vmess: ServerPacketConn 需 UDP 握手建立的 stream")
	}
	if pc.pc == nil {
		return nil, errors.New("vmess: 未捕获到 UDP PacketConn")
	}
	return &packetConn{pc: pc.pc, dst: dst, below: pc.Stream}, nil
}

// packetCarrier 是 UDP 握手结果的载体 stream:携带 sing 捕获的 PacketConn + 控制 below。
type packetCarrier struct {
	link.Stream // 传输 below
	pc          N.PacketConn
}

func (s *packetCarrier) Unwrap() any { return s.Stream }

// packetConn 把 sing PacketConn 桥成 NTR link.PacketConn(单目标,dst 恒为握手目标)。
type packetConn struct {
	pc    N.PacketConn // sing 侧:ReadPacket/WritePacket 帧对齐,一次一个完整 datagram
	dst   addr.Socksaddr
	below link.Stream
}

var _ link.PacketConn = (*packetConn)(nil)

// ReadPacket 读一个 datagram 到 b。★走 sing 的 ReadPacket(→ ExtendedReader.ReadBuffer),它按 chunk
// 长度前缀读【恰好一个】datagram,严格保持数据报边界。不能用 NetPacketConn.ReadFrom([]byte)——sing
// 的 ReadFrom 走 AEADReader.Read(p) 是【流式】读,对开了 GlobalPadding/ChunkMasking 或 XUDP 的对端
// (xray 的 vmess UDP)会破坏报边界甚至读不出首包。sing-box/mihomo 一律用 ReadBuffer 收 UDP,故互通。
// 读进 sing 缓冲后拷入 NTR b:≤ 容量拷入;超容量(极罕见巨型报)丢弃继续,不拆分、不破坏边界。
func (c *packetConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	for {
		sb := singbuf.NewSize(64 * 1024)
		if _, err := c.pc.ReadPacket(sb); err != nil {
			sb.Release()
			return addr.Socksaddr{}, err
		}
		data := sb.Bytes()
		b.Reset()
		if len(data) > b.Tailroom() {
			sb.Release()
			continue // 巨型数据报超 buf 容量 → 丢弃继续(UDP 可丢),不破坏边界
		}
		copy(b.ExtendTail(len(data)), data)
		sb.Release()
		return c.dst, nil
	}
}

// WritePacket 把 b(payload)作为一个 datagram 写回。★携带真实回程 dst:XUDP(serverMuxPacketConn)
// 每包头自带源地址,dst 必须写对,否则对端(xray)无法把回包对上 socks 关联而丢弃;普通 serverPacketConn
// 忽略 dst(单目标),传对亦无害。用带前置 headroom 的 sing 缓冲,让 sing 就地前插各自的包头。
func (c *packetConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	payload := b.Bytes()
	// 容量 = 前置头 + payload + 后置尾:前留 XUDP/长度头,后留 AEAD tag + padding。
	sb := singbuf.NewSize(writeFrontHeadroom + len(payload) + writeRearHeadroom)
	sb.Resize(writeFrontHeadroom, 0) // start=end=headroom;留出前插空间(尾空间自然剩在 cap 里)
	if _, err := sb.Write(payload); err != nil {
		sb.Release()
		return err
	}
	// ★ sing 的 WriteBuffer 内部 defer buffer.Release() —— 已转移所有权,此处【不能】再 Release(会双释放毁池)。
	return c.pc.WritePacket(sb, toSing(dst))
}

func (c *packetConn) Close() error {
	_ = c.pc.Close()
	return c.below.Close()
}
func (c *packetConn) LocalAddr() net.Addr           { return c.below.LocalAddr() }
func (c *packetConn) SetDeadline(t time.Time) error { return c.below.SetDeadline(t) }
func (c *packetConn) Unwrap() any                   { return c.below }
