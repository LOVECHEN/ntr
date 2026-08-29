package reverse

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
	"github.com/LOVECHEN/ntr/muxcool"
)

// PacketHandshaker 是 Handshaker 的 UDP 扩展:把 UDP 握手后的 stream 适配成用户侧多目标
// PacketConn(service.ProxyInbound 满足)。Portal 据此把 UDP 用户流桥到反连隧道。
type PacketHandshaker interface {
	ServerPacketConn(hs link.Stream, dst addr.Socksaddr) (link.PacketConn, error)
}

// ErrNoBridge 表示当前无可用反连隧道(Bridge 未连上 / 全部 DRAIN)。
var ErrNoBridge = errors.New("reverse: 无可用反连隧道(Bridge 未就绪)")

// ErrReverseUDP 表示 Portal 暂未接入反向 UDP(TCP MVP;UDP 后置)。
var ErrReverseUDP = errors.New("reverse: portal 暂未接入反向 UDP")

// Portal 是公网侧入站处理器:复用一条已编译的服务端栈(Handshaker)做握手,然后:
//   - 目标 == Control:这是 Bridge 控制连接 —— 把 stream 抬成 Mux.cool 客户端 worker 入池、
//     开控制心跳、阻塞跑解复用读环(隧道存活期)。
//   - 目标 != Control:这是用户连接 —— 挑一个活跃隧道开子流,把用户流 relay 到子流(反向复用回 Bridge)。
//
// 它是 endpoint.InboundHandler,可直接挂在任意 listener 上(经 service.Serve)。
type Portal struct {
	HS       Handshaker    // 握手(传输层 + 协议),通常 *service.ProxyInbound
	Control  string        // 控制域:Bridge 连接的目标 fqdn(默认 DefaultControlDomain)
	Interval time.Duration // 控制心跳周期(默认 10s)

	pool pool
}

var _ endpoint.InboundHandler = (*Portal)(nil)

// SessionDispatcher 让自管监听的会话式协议(anytls/hy1/hy2/tuic —— 每流已握手、含目标)把流
// 交给 reverse Portal 反连派发,而非 relay 到本地出站。*Portal 满足它 —— 会话式协议据此
// 【免修改协议本身】即可当反连隧道端(只在其入站接线处注入本接口)。
type SessionDispatcher interface {
	Dispatch(ctx context.Context, hs link.Stream, dst addr.Socksaddr, network endpoint.Network, udp func() (link.PacketConn, error)) error
}

var _ SessionDispatcher = (*Portal)(nil)

// HandleStream:流式协议入站 —— 先经 Handshaker 握手,再交 Dispatch 反连派发。
func (p *Portal) HandleStream(ctx context.Context, s link.Stream, md *endpoint.Metadata) error {
	hs, req, err := p.HS.Handshake(ctx, s, md)
	if err != nil {
		return err
	}
	var udp func() (link.PacketConn, error)
	if ph, ok := p.HS.(PacketHandshaker); ok {
		udp = func() (link.PacketConn, error) { return ph.ServerPacketConn(hs, req.Dst) }
	}
	return p.Dispatch(ctx, hs, req.Dst, req.Network, udp)
}

// Dispatch 对一条【已握手】的流(hs + dst + network)做反连派发,供流式(HandleStream)与会话式
// (SessionDispatcher)入站共用:控制域→入池跑解复用;TCP 用户→挑隧道开子流 relay;UDP 用户→桥到
// mux UDP(需 udp 提供用户侧 PacketConn;会话式暂传 nil = 反连 UDP 后置)。
func (p *Portal) Dispatch(ctx context.Context, hs link.Stream, dst addr.Socksaddr, network endpoint.Network, udp func() (link.PacketConn, error)) error {
	control := p.Control
	if control == "" {
		control = DefaultControlDomain
	}

	// —— Bridge 控制连接:目标域 == 控制域 —— 把这条隧道纳入池。
	if dst.IsFqdn() && dst.Fqdn == control {
		w := muxcool.NewClientWorker(hs)
		p.pool.add(w)
		defer p.pool.remove(w)
		// ctx 取消(全局关停)→ w.Close():打断阻塞在 ReadFrame 或卡在 bufPipe.Write 的 Run,
		// 并 close done 让 pool 立刻剔除本隧道,不再向卡死隧道派新子流。
		stop := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = w.Close()
			case <-stop:
			}
		}()
		defer close(stop)
		interval := p.Interval
		if interval <= 0 {
			interval = 10 * time.Second
		}
		if err := w.StartControl(interval); err != nil {
			_ = hs.Close()
			return err
		}
		return w.Run() // 阻塞:解复用回程,直到隧道断
	}

	// —— UDP 用户连接:桥到反连隧道(每 target 一条 mux UDP 子流,Bridge 侧落地本地)——
	if network == endpoint.NetworkUDP {
		if udp == nil {
			_ = hs.Close()
			return ErrReverseUDP
		}
		userPC, err := udp() // 用户侧多目标 PacketConn(userPC.Close 关 hs)
		if err != nil {
			_ = hs.Close()
			return err
		}
		w := p.pool.pick()
		if w == nil {
			_ = userPC.Close()
			return ErrNoBridge
		}
		return relayUDP(userPC, w.NewPacketConn()) // 用户 UDP ⇄ mux UDP 双向搬
	}

	// —— TCP 用户连接:反向复用回某条隧道 ——
	w := p.pool.pick()
	if w == nil {
		_ = hs.Close()
		return ErrNoBridge
	}
	sub, err := w.OpenStream(toMuxNetwork(network), toMuxAddr(dst), dst.Port)
	if err != nil {
		_ = hs.Close()
		return err
	}
	return relay.Relay(hs, netStream{sub}) // Relay 内部两端收尾
}

// HandlePacket:Portal 不处理原生 PacketConn 形状入站(反向 UDP 后置)。
func (p *Portal) HandlePacket(context.Context, link.PacketConn, *endpoint.Metadata) error {
	return ErrReverseUDP
}

// TunnelCount 返回当前池内活跃隧道数(观测/测试用)。
func (p *Portal) TunnelCount() int { return p.pool.size() }

// relayUDP 把用户侧多目标 PacketConn(user)⇄ 反连隧道的 mux PacketConn(mux)双向搬:
// 上行按 dst 经 mux 开/复用 UDP 子流送到 Bridge 落地;下行 mux 回程按子流 target 还原 src
// 写回用户。任一端出错即收尾关两端。
func relayUDP(user link.PacketConn, mux net.PacketConn) error {
	defer user.Close()
	defer mux.Close()
	errc := make(chan error, 2)
	go func() { // 上行:user → mux
		b := buf.New()
		defer b.Release()
		for {
			b.Reset()
			dst, err := user.ReadPacket(b)
			if err != nil {
				errc <- err
				return
			}
			if _, err := mux.WriteTo(b.Bytes(), socksNetAddr{dst}); err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() { // 下行:mux → user
		p := make([]byte, 64*1024)
		for {
			n, src, err := mux.ReadFrom(p)
			if err != nil {
				errc <- err
				return
			}
			sa, ok := src.(socksNetAddr)
			if !ok {
				continue // 非本编码来源(不应发生),跳过
			}
			wb := buf.New()
			if _, werr := wb.Write(p[:n]); werr != nil {
				wb.Release()
				continue // 超 buf 容量的巨型数据报 → 丢弃(不截断发错)
			}
			werr := user.WritePacket(wb, sa.a)
			wb.Release()
			if werr != nil {
				errc <- werr
				return
			}
		}
	}()
	return <-errc
}

// socksNetAddr 把 addr.Socksaddr 包成 net.Addr,供 mux net.PacketConn.WriteTo 保留域名/端口;
// muxPacketConn 以之为子流 target,回程 ReadFrom 原样返回,故可直接断言取回 addr.Socksaddr。
type socksNetAddr struct{ a addr.Socksaddr }

func (s socksNetAddr) Network() string { return "udp" }
func (s socksNetAddr) String() string  { return s.a.String() }
