package shadowsocks

import (
	"context"
	"io"
	"net"
	"time"

	singbuf "github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// Shadowsocks 的 UDP 是【原生 datagram】——每包独立 AEAD 加密、直发上游 UDP 端口,不 over stream。
// 故实现 NativePacketConnClient(而非 PacketConnClient):自建到 server 的 connected UDP socket,
// 交 sing 的 Method.DialPacketConn 套 SS UDP 封装(2022 与经典两代同一 API),再桥成 link.PacketConn。
// 与 xray / mihomo / sing-box 的 SS UDP 线级互通(封装全由 sing 产出/消费)。
var _ proxy.NativePacketConnClient = (*Proxy)(nil)

// DialNativePacketConn 实现 proxy.NativePacketConnClient:拨 connected UDP socket 到上游,
// 用连接级 method 套 SS UDP 封装,桥成单目标 link.PacketConn(dst 恒为本次关联目标)。
func (p *Proxy) DialNativePacketConn(_ context.Context, server string, _ []byte, dst addr.Socksaddr) (link.PacketConn, error) {
	udp, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	sc := p.method.DialPacketConn(udp) // sing 侧:ReadPacket/WritePacket 帧对齐,每次一个完整 datagram
	return &packetConn{
		pc:    sc,
		conn:  udp,
		dst:   dst,
		front: N.CalculateFrontHeadroom(sc), // 运行时问 sing:两代 SS 头长不同,不写死
		rear:  N.CalculateRearHeadroom(sc),  // AEAD tag 尾空间
	}, nil
}

// packetConn 把 sing 的 SS UDP PacketConn 桥成 NTR link.PacketConn(单目标,dst 恒为握手目标)。
type packetConn struct {
	pc    N.PacketConn
	conn  net.Conn // 底层 UDP socket(SetDeadline/LocalAddr/Close 落到它)
	dst   addr.Socksaddr
	front int
	rear  int
}

var _ link.PacketConn = (*packetConn)(nil)

// ReadPacket 读一个 datagram 到 b。★走 sing 的 ReadPacket(帧对齐,读恰好一个完整 SS UDP 包并解密),
// 严格保持数据报边界。读进 sing 缓冲后拷入 NTR b:超容量的巨型报丢弃继续(UDP 可丢),不拆分。
// SS 单目标关联下回包源恒为 c.dst,直接返回它(与 vmess 单目标一致)。
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
			continue // 巨型数据报超 buf 容量 → 丢弃继续,不破坏边界
		}
		copy(b.ExtendTail(len(data)), data)
		sb.Release()
		return c.dst, nil
	}
}

// WritePacket 把 b(payload)作为一个 SS UDP datagram 加密后发往上游。用带前置/后置 headroom 的
// sing 缓冲,让 sing 就地前插 SS 包头(session/packetId/timestamp/addr…)、后追 AEAD tag。
func (c *packetConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	payload := b.Bytes()
	sb := singbuf.NewSize(c.front + len(payload) + c.rear)
	sb.Resize(c.front, 0) // start=end=front;留出前插空间(尾空间自然剩在 cap 里)
	if _, err := sb.Write(payload); err != nil {
		sb.Release()
		return err
	}
	// ★ sing 的 WritePacket 内部 defer buffer.Release() —— 已转移所有权,此处【不能】再 Release。
	return c.pc.WritePacket(sb, toSing(dst))
}

func (c *packetConn) Close() error                  { return c.conn.Close() }
func (c *packetConn) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *packetConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *packetConn) Unwrap() any                   { return c.conn }

// ────────────────────────────── 服务端(入站)────────────────────────────────
// SS UDP 入站也是原生 datagram(无先导 stream),故实现 proxy.PacketServer:核心把绑好的 UDP
// socket 交来,这里跑读环 + 喂 sing Service(内部按源做 NAT、解密、解目标),对每条逻辑流回调 sink
// 交出一条已解密的多目标 link.PacketConn 给核心 udpNAT 落地。与 xray/mihomo/sing-box 的 SS UDP 互通。
var _ proxy.PacketServer = (*Proxy)(nil)

// udpSinkKey 把核心提供的 sink(每逻辑流一条 link.PacketConn)经 ctx 传到 sing 的 handler
// (NewPacketConnection)。sing 从首包 ctx 建每源会话 goroutine,故 sink 随之到达。
type udpSinkKey struct{}

// 服务端回程写缓冲的 headroom 下限:兜底 sing headroom 查询(理应穿透到 serverPacketWriter,
// 但即便查不到也不能少于此)。2022 回程头最坏 = nonce24+overhead16+16+type1+ts8+padlen2+pad900+
// socksaddr259 ≈ 1226,取 1500 稳覆盖;经典远小于此。rear = AEAD overhead,取 64 稳。
const (
	svcFrontFloor = 1500
	svcRearFloor  = 64
)

// ServePacket 实现 proxy.PacketServer:在 pc 上跑 SS UDP 入站读环,阻塞至 ctx 取消 / socket 关闭。
func (p *Proxy) ServePacket(ctx context.Context, pc net.PacketConn, sink func(link.PacketConn)) error {
	bind := &singBind{pc: pc}
	sctx := context.WithValue(ctx, udpSinkKey{}, sink)
	go func() { <-ctx.Done(); _ = pc.Close() }() // ctx 取消 → 关 socket 解阻塞读

	rbuf := make([]byte, 64*1024)
	for {
		n, src, err := pc.ReadFrom(rbuf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		sb := singbuf.NewSize(n)
		_, _ = sb.Write(rbuf[:n]) // 必须拷:rbuf 下轮复用;sing 成功路径会接管并最终 Release
		md := M.Metadata{Source: M.SocksaddrFromNet(src)}
		if err := p.service.NewPacket(sctx, bind, sb, md); err != nil {
			sb.Release() // 解密/解析失败(探测/坏包常态):sing 未接管,我 Release,单坏包不拖垮读环
		}
	}
}

// singBind 把裸 UDP socket 抬成 sing 的 N.PacketConn,仅供 SS Service 回程写:
// serverPacketWriter 末尾 conn.WritePacket(encrypted, clientSource) → 这里 pc.WriteTo 发回客户端。
// sing 从不读它(读环在 ServePacket 自持),故 ReadPacket 只占位。
type singBind struct{ pc net.PacketConn }

var _ N.PacketConn = (*singBind)(nil)

func (b *singBind) WritePacket(buffer *singbuf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release() // sing 写惯例:转移所有权,写完释放
	_, err := b.pc.WriteTo(buffer.Bytes(), destination.UDPAddr())
	return err
}
func (b *singBind) ReadPacket(*singbuf.Buffer) (M.Socksaddr, error) { return M.Socksaddr{}, io.EOF }
func (b *singBind) Close() error                       { return nil } // socket 生命周期在 ServePacket,不由 bind 关
func (b *singBind) LocalAddr() net.Addr                { return b.pc.LocalAddr() }
func (b *singBind) SetDeadline(time.Time) error        { return nil }
func (b *singBind) SetReadDeadline(time.Time) error    { return nil }
func (b *singBind) SetWriteDeadline(time.Time) error   { return nil }

// newServerPacketConn 把 sing 的已解密 natConn 桥成 NTR link.PacketConn(多目标)。
func newServerPacketConn(pc N.PacketConn) *serverPacketConn {
	front := N.CalculateFrontHeadroom(pc)
	if front < svcFrontFloor {
		front = svcFrontFloor
	}
	rear := N.CalculateRearHeadroom(pc)
	if rear < svcRearFloor {
		rear = svcRearFloor
	}
	return &serverPacketConn{pc: pc, front: front, rear: rear}
}

// serverPacketConn 桥 sing 已解密 natConn ↔ NTR link.PacketConn。读=客户端→各真实目标(每包自带
// dst,多目标);写=真实目标→客户端的回包(sing 重加密后经 singBind 发回)。交核心 udpNAT。
type serverPacketConn struct {
	pc    N.PacketConn
	front int
	rear  int
}

var _ link.PacketConn = (*serverPacketConn)(nil)

func (c *serverPacketConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	for {
		sb := singbuf.NewSize(64 * 1024)
		dst, err := c.pc.ReadPacket(sb)
		if err != nil {
			sb.Release()
			return addr.Socksaddr{}, err
		}
		data := sb.Bytes()
		b.Reset()
		if len(data) > b.Tailroom() {
			sb.Release()
			continue // 巨型报超 buf 容量 → 丢弃继续
		}
		copy(b.ExtendTail(len(data)), data)
		sb.Release()
		return toNTR(dst), nil // ★ 多目标:返回本包自带的 SS 目标
	}
}

func (c *serverPacketConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	payload := b.Bytes()
	sb := singbuf.NewSize(c.front + len(payload) + c.rear)
	sb.Resize(c.front, 0)
	if _, err := sb.Write(payload); err != nil {
		sb.Release()
		return err
	}
	return c.pc.WritePacket(sb, toSing(dst)) // sing 内部 defer Release,不再手放
}

func (c *serverPacketConn) Close() error { return c.pc.Close() }
func (c *serverPacketConn) LocalAddr() net.Addr {
	return c.pc.LocalAddr()
}
func (c *serverPacketConn) SetDeadline(t time.Time) error { return c.pc.SetReadDeadline(t) }
func (c *serverPacketConn) Unwrap() any                   { return nil }
