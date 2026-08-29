package service

import (
	"context"
	"fmt"

	"github.com/LOVECHEN/ntr/core/compile"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
	"github.com/LOVECHEN/ntr/outbound/upstream"
)

// LayerSpec 是一层的名字 + 其配置节点。名字经 registry 解析到 Descriptor;
// 书写顺序不重要 —— compile.Order 按 Band 定序。
type LayerSpec struct {
	Name string
	Node *spec.Node
}

// buildStack 是入站/出站共用的骨架:按名解析描述符 → compile.Order 定序+邻接校验 →
// 底→顶构建;返回顶层之下的传输链(已建)与顶层协议对象(未断言角色,交调用方)。
// 入站断言 proxy.Server、出站断言 proxy.Client —— 唯一差别只在终端角色。
//
// base 是可选的【栈底基础传输】(mkcp 等 UDP-base):若最底层实现 BaseTransport,它替代默认 TCP,
// 单独返回(不进 below 的 StreamTransport 链),由出站/入站分别以 DialBase/ListenBase 驱动。
func buildStack(ctx context.Context, layers []LayerSpec) (base transport.BaseTransport, below []transport.StreamTransport, top any, err error) {
	if len(layers) == 0 {
		return nil, nil, nil, fmt.Errorf("service: 空层集")
	}
	descs := make([]registry.AnyDescriptor, 0, len(layers))
	node := make(map[string]*spec.Node, len(layers))
	for _, l := range layers {
		d, ok := registry.Lookup(l.Name)
		if !ok {
			return nil, nil, nil, fmt.Errorf("service: 未知层 %q", l.Name)
		}
		if _, dup := node[l.Name]; dup {
			return nil, nil, nil, fmt.Errorf("service: 层 %q 重复", l.Name)
		}
		descs = append(descs, d)
		node[l.Name] = l.Node
	}

	ordered, err := compile.Order(descs) // 底→顶 + 三重邻接校验
	if err != nil {
		return nil, nil, nil, err
	}

	for i, d := range ordered {
		cfg, err := d.Parse(node[d.Name()])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("service: 解析层 %q 配置:%w", d.Name(), err)
		}
		built, err := d.Build(ctx, cfg, nil) // 层对象连接级复用;按连接包裹在 Handle/Dial
		if err != nil {
			return nil, nil, nil, fmt.Errorf("service: 构建层 %q:%w", d.Name(), err)
		}
		if i == len(ordered)-1 { // 顶层 = 终端协议
			top = built
			return base, below, top, nil
		}
		if i == 0 { // 最底层可为 BaseTransport(mkcp 等 UDP-base):单独收,不入 below
			if bt, ok := built.(transport.BaseTransport); ok {
				base = bt
				continue
			}
		}
		st, ok := built.(transport.StreamTransport) // 其余须为传输变换器
		if !ok {
			return nil, nil, nil, fmt.Errorf("service: 层 %q 不是 StreamTransport(不能叠在协议之下)", d.Name())
		}
		below = append(below, st)
	}
	return base, below, top, nil
}

// BuildInbound 把一组层(如 tls + vless)编译成服务端栈并接成 ProxyInbound。
// 顶层须实现 proxy.Server。角色靠接口断言,不靠协议名 switch。
// 第二返回值 base 非 nil 表示栈底是 UDP-base 传输(mkcp):调用方须用 base.ListenBase 自管监听
// (而非默认 TCP accept),accept 出的每条流仍交本 ProxyInbound.HandleStream 落地。
func BuildInbound(ctx context.Context, layers []LayerSpec, auth proxy.Authenticator, out OutboundResolver) (*ProxyInbound, transport.BaseTransport, error) {
	base, below, top, err := buildStack(ctx, layers)
	if err != nil {
		return nil, nil, err
	}
	srv, ok := top.(proxy.Server)
	if !ok {
		return nil, nil, fmt.Errorf("service: 顶层不是 proxy.Server(不能作入站终端)")
	}
	return &ProxyInbound{Below: below, Proxy: srv, Auth: auth, Out: out}, base, nil
}

// ServeBase 在 BaseTransport 的监听上跑 accept 环:每条可靠流交 handler.HandleStream 落地
// (与 TCP 版 Serve 同构,仅监听源不同)。阻塞至 ctx 取消或监听关闭。
func ServeBase(ctx context.Context, ln transport.BaseListener, h endpoint.InboundHandler) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		s, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go func(s link.Stream) {
			md := &endpoint.Metadata{}
			if err := h.HandleStream(ctx, s, md); err != nil && !isNormalClose(err) {
				debugf("mkcp 入站处理失败 src=%v: %v", s.RemoteAddr(), err)
			}
		}(s)
	}
}

// BuildOutbound 把一组层编译成客户端栈并接成 upstream.Outbound(拨 server)。
// 顶层须实现 proxy.Client;若其还实现 proxy.CredentialCodec,则由它把 secret 派生成
// 客户端出示的 key(否则按原始字节)—— 凭据语义归插件,组装侧零协议 switch。
func BuildOutbound(ctx context.Context, server string, layers []LayerSpec, secret string) (*upstream.Outbound, error) {
	base, below, top, err := buildStack(ctx, layers)
	if err != nil {
		return nil, err
	}
	cli, ok := top.(proxy.Client)
	if !ok {
		return nil, fmt.Errorf("service: 顶层不是 proxy.Client(不能作出站终端)")
	}
	key := []byte(secret)
	if cc, ok := top.(proxy.CredentialCodec); ok {
		k, err := cc.ClientKey(secret)
		if err != nil {
			return nil, fmt.Errorf("service: 派生客户端凭据:%w", err)
		}
		key = k
	}
	o := &upstream.Outbound{Server: server, Below: below, Client: cli, Key: key}
	if base != nil { // UDP-base(mkcp):以 DialBase 替代 TCP 拨号
		o.BaseDial = base.DialBase
	}
	return o, nil
}
