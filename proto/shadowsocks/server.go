package shadowsocks

import (
	"context"
	"errors"
	"net"

	"github.com/metacubex/sing/common/auth"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// resultKey 是把每次握手的结果holder塞进 ctx 的键(共享 service + 并发安全:每调用一份 holder)。
type resultKey struct{}

type result struct {
	conn net.Conn
	dst  M.Socksaddr
	refs userRefs // 顶层 users 的 tag → 归属表(空 = 单用户口)
	cred cred.Ref // 命中的归属;缺省 Ambient
}

// userRefs 是顶层 users 经 UserRegistrar 注入的 tag → 归属表。sing 的 MultiService 命中 EIH 用户后
// 以 auth.ContextWithUser(ctx, tag) 回调 handler,这里按 tag 映回 cred.Ref —— 多用户匹配在 sing 内部,
// NTR 只做"回读 + 映射",不碰线格式。
type userRefs struct{ m map[string]cred.Ref }

func (u *userRefs) set(tag string, ref cred.Ref) {
	if u.m == nil {
		u.m = make(map[string]cred.Ref)
	}
	u.m[tag] = ref
}

func (u userRefs) lookup(ctx context.Context) (cred.Ref, bool) {
	tag, ok := auth.UserFromContext[string](ctx)
	if !ok {
		return cred.Ref{}, false
	}
	r, ok := u.m[tag]
	return r, ok
}

// captureHandler 是喂给 sing service 的处理器:从 ctx 取本次 holder,捕获解密后的 relay conn +
// 目标,立即返回(sing 的 newConnection 末尾即 handler.NewConnection,之后不关 conn,故可同步捕获)。
type captureHandler struct{}

func (captureHandler) NewConnection(ctx context.Context, conn net.Conn, md M.Metadata) error {
	if r, ok := ctx.Value(resultKey{}).(*result); ok {
		r.conn = conn
		r.dst = md.Destination
		if ref, ok := r.refs.lookup(ctx); ok { // MultiService 命中的 EIH 用户 → 该 BillID
			r.cred = ref
		}
	}
	return nil
}

// NewPacketConnection 由 sing 在每源会话 goroutine 内调用(见 ServePacket)。从 ctx 取核心 sink,
// 把已解密的多目标 natConn 桥成 link.PacketConn 交出去。★必须【同步阻塞】—— sink 内跑 udpNAT,
// 返回后 sing 才 Close(conn),这才是正确生命周期(若异步起,conn 会被立刻关闭)。
func (captureHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, _ M.Metadata) error {
	sink, ok := ctx.Value(udpSinkKey{}).(func(link.PacketConn))
	if !ok || sink == nil {
		return errors.New("shadowsocks: 无 UDP sink(未经 ServePacket 驱动)")
	}
	sink(newServerPacketConn(conn))
	return nil
}

func (captureHandler) NewError(context.Context, error) {}

// ServerHandshake 实现 proxy.Server:用共享 service 读 SS 请求(含 replay 校验),同步捕获
// relay conn + 目标,返回承载 payload 的 stream + Request。SS 单密码鉴权 → Ambient。
func (p *Proxy) ServerHandshake(ctx context.Context, below link.Stream, _ proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	if p.service == nil {
		return nil, nil, errors.New("shadowsocks: password 为 iPSK:uPSK 多段(2022 多用户客户端写法),此口只能作出站;入站请写单段 iPSK 并把 uPSK 放顶层 users")
	}
	r := &result{refs: p.users, cred: cred.Ref{ID: cred.Ambient}}
	cctx := context.WithValue(ctx, resultKey{}, r)
	if err := p.service.NewConnection(cctx, below, M.Metadata{}); err != nil {
		return nil, nil, err
	}
	if r.conn == nil {
		return nil, nil, errors.New("shadowsocks: 未捕获到连接")
	}
	dst := toNTR(r.dst)
	network := endpoint.NetworkTCP
	if isUoTMagic(dst) {
		// UDP-over-TCP:客户端把 UDP 关联封成一条 SS 流到魔术地址;归一化为 UDP,交 PacketConnServer
		// 在流上读 uot 分帧(自动检测,与 sing-box/mihomo 一致,不需配置开关)。
		network = endpoint.NetworkUDP
	}
	req := &proxy.Request{
		Cred:    r.cred, // 单用户口 = Ambient;2022 多用户口 = EIH 命中的 BillID(UDP 侧归属见 NewPacketConnection 注)
		Network: network,
		Dst:     dst,
	}
	return &streamWrap{Conn: r.conn, below: below}, req, nil
}
