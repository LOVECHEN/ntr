package service

import (
	"context"
	"net"
	"net/netip"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
	"github.com/LOVECHEN/ntr/meter"
)

// Admitter 是接入的【唯一入口】的无字段实现:所有落地路径(流式 ProxyInbound 的普通 TCP / UDP-over-stream /
// mux 承载 / 库内 mux 子流,以及会话式协议 anytls/hy2/tuic… 的 dispatch)都经它,不许绕(承 §6.2/§6.4bis)。
//
// 抽成独立件的原因:会话式协议不走 ProxyInbound(不是也不内嵌它),但接入逻辑与之完全同构 —— 连接闸 +
// mem-guard 软阈值 + 按用户计量 + 热开关。ProxyInbound 内嵌 Admitter 委托,会话式 dispatch 直接持一个
// Admitter,两条路共用同一份接入实现,守住"唯一入口"不变式。
type Admitter struct {
	Meter    *meter.Registry // 非 nil = 开启按用户计量(承 §5);nil = 关闭、零成本
	Gates    []*meter.Gate   // 全局 + 每口连接闸/限速(承 §6.2 层1/2;可空)
	MemGuard *meter.MemGuard // 防 OOM 软阈值拒新(承 §6.4bis;nil = 不设,AdmitOK 恒真零成本)
}

// AdmitConn 是接入的唯一入口(所有落地路径都经此,不许绕):
//  0. mem-guard 软阈值(§6.4bis.2):内存进 soft/hard 档 → 拒新(已建立连接不动);最先判,护进程存亡;
//  1. 全局 / 每口连接闸(§6.2 层1/2,max-conns):接入 CAS,叠加顺序 全局→口,任一超即拒;
//  2. 按用户计量 + 热开关 + 每用户限额(开启时):登记到 who 的 Cell(kill=关 closers);Disable(§6.5)/
//     触顶(max-conns/max-ips,§6.3)→ 拒新、立即关。
//
// 返回本连接的计量器(nil = 计量关闭且无闸,零成本)+ release(调用方 defer:注销连接 + 放闸)。
// 被拒返回 errAdmissionRejected,closers 已关。
func (a *Admitter) AdmitConn(who cred.ID, src addr.Socksaddr, closers ...interface{ Close() error }) (*meter.Meter, func(), error) {
	closeAll := func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}
	if !a.MemGuard.AdmitOK() { // §6.4bis.2 内存软阈值:拒新(计数在 MemGuard 内);护进程最先判
		closeAll()
		return nil, nil, errAdmissionRejected
	}
	for i, g := range a.Gates {
		if !g.TryAcquire() {
			for _, gg := range a.Gates[:i] {
				gg.Release()
			}
			closeAll()
			return nil, nil, errAdmissionRejected
		}
	}
	releaseGates := func() {
		for _, g := range a.Gates {
			g.Release()
		}
	}
	if a.Meter != nil {
		mm, done, ok := a.Meter.Open(who, src.Addr, closeAll)
		if !ok {
			releaseGates()
			closeAll()
			return nil, nil, errAdmissionRejected
		}
		return mm.WithGates(a.Gates), func() { done(); releaseGates() }, nil
	}
	if len(a.Gates) > 0 {
		return meter.GateMeter(a.Gates), releaseGates, nil // 仅全局/每口限速(未开按用户计量)
	}
	return nil, func() {}, nil
}

// Admit = AdmitConn + 包客户端侧流 s(Read=上行、Write=下行,稀疏累计到 who;gate 的 rate 也在稀疏点一并
// throttle)。返回包好的流 + release。
func (a *Admitter) Admit(who cred.ID, src addr.Socksaddr, s link.Stream, closers ...interface{ Close() error }) (link.Stream, func(), error) {
	m, release, err := a.AdmitConn(who, src, closers...)
	if err != nil {
		return nil, nil, err
	}
	if m != nil {
		s = meter.Wrap(s, m)
	}
	return s, release, nil
}

// SessionAdmit 建 endpoint.AdmitHook:读身份 → Admit(闸+计量+mem-guard)→ 返回计量流 + release,
// 【不代管 relay】。供 hysteria v1 这类"落地前需回协议特定握手信令"的会话式协议:它拿到计量流后先做
// 自己的 ReportConnHandshakeSuccess(在裸 conn 上),再 relay(计量流)。readUser/refs 语义同 SessionDispatch。
func SessionAdmit(adm *Admitter, refs map[string]cred.ID, readUser func(context.Context) (string, bool)) endpoint.AdmitHook {
	return func(ctx context.Context, s link.Stream) (link.Stream, func(), error) {
		ap := srcAddrPort(s)
		return adm.Admit(sessionWho(ctx, refs, readUser), addr.Socksaddr{Addr: ap.Addr(), Port: ap.Port()}, s)
	}
}

// sessionWho 按 readUser 从 ctx 读身份 tag,命中 refs 得 cred.ID,否则 Ambient。
func sessionWho(ctx context.Context, refs map[string]cred.ID, readUser func(context.Context) (string, bool)) cred.ID {
	if readUser != nil {
		if tag, ok := readUser(ctx); ok {
			if id, ok2 := refs[tag]; ok2 {
				return id
			}
		}
	}
	return cred.Ambient
}

// SessionPacketDispatch 建 endpoint.PacketDispatch(与 SessionDispatch 对位的 UDP 版):会话式入站解出的客户端
// 侧数据报连接,先按 readUser 从 ctx 读身份 → 过 Admitter(连接闸 + 按用户计量 + mem-guard,一个 UDP 会话
// 计一条连接)→ 包计量(payload 口径:ReadPacket 计上行、WritePacket 计下行)→ udpNAT 按包目标拆分、逐目标
// 经 out 路由并回写来源(与流式入站 UDP 同一条路径)。来源 IP 取自 pc 的 RemoteAddr()(实现了才有;供 max-ips)。
// adm 为 nil 时不准入不计量。返回时 pc 已关。
func SessionPacketDispatch(out endpoint.Outbound, adm *Admitter, refs map[string]cred.ID, readUser func(context.Context) (string, bool)) endpoint.PacketDispatch {
	return func(ctx context.Context, pc link.PacketConn) error {
		defer pc.Close()
		if adm != nil {
			ap := packetSrc(pc)
			m, release, err := adm.AdmitConn(sessionWho(ctx, refs, readUser), addr.Socksaddr{Addr: ap.Addr(), Port: ap.Port()}, pc)
			if err != nil {
				return err // 被拒时 pc 已关
			}
			defer release()
			if m != nil {
				pc = meter.WrapPacket(pc, m)
			}
		}
		return udpNAT(ctx, pc, StaticOutbound{Out: out})
	}
}

// packetSrc 取数据报连接的客户端来源(pc 实现 RemoteAddr() 才有;否则零值)。
func packetSrc(pc link.PacketConn) netip.AddrPort {
	if r, ok := pc.(interface{ RemoteAddr() net.Addr }); ok {
		if ra := r.RemoteAddr(); ra != nil {
			if ap, err := netip.ParseAddrPort(ra.String()); err == nil {
				return ap
			}
		}
	}
	return netip.AddrPort{}
}

// SessionDispatch 建【会话式协议】的计量版 endpoint.StreamDispatch:每条库内解复用出的已握手流,先按
// readUser 从 ctx 读身份 tag(命中 refs 得 cred.ID,缺省 Ambient)→ 过 Admitter(连接闸 + 按用户计量 +
// mem-guard,与流式栈同一唯一入口)→ 包计量流 → 拨出站 relay。供 anytls/hy2/tuic… 这些"库内自管会话、
// 不走 ProxyInbound"的协议接入第4章 users + §5/§6 计量限额;协议侧 routeHandler 一行不改(只需把本 dispatch
// 传进 NewInbound 的 dispatch 位)。反连 portal(ControlDomain)不走这里,由 config 保持原样(隧道载体不计量)。
//
// readUser 是协议侧提供的身份读取器(各协议的底层库用不同 sing fork 的 auth.ContextWithUser 写入 tag,
// 故读取也须用同一 fork);refs 为空(垫片/无顶层 users)时恒落 Ambient,gate + mem-guard 仍照常生效。
func SessionDispatch(out endpoint.Outbound, adm *Admitter, refs map[string]cred.ID, readUser func(context.Context) (string, bool)) endpoint.StreamDispatch {
	return func(ctx context.Context, s link.Stream, dst addr.Socksaddr, _ endpoint.Network) error {
		ap := srcAddrPort(s)
		ms, release, err := adm.Admit(sessionWho(ctx, refs, readUser), addr.Socksaddr{Addr: ap.Addr(), Port: ap.Port()}, s)
		if err != nil {
			return err // Admit 被拒时已关 s
		}
		defer release()
		up, err := out.DialStream(ctx, dst)
		if err != nil {
			_ = ms.Close()
			return err
		}
		return relay.Relay(ms, up)
	}
}
