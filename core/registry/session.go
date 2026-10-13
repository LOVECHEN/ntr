package registry

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/spec"
)

// 会话式协议插件注册表 —— 「加协议核心零 diff」在会话式协议上的落点。
//
// 会话式协议(QUIC 系等)自管监听、每流自带目标、自己做多路复用,不走分层变换器栈(Descriptor/Band),
// 故单开一张表。协议在自己包的 init() 里 RegisterSession,由 manifest/ 一行 blank-import 决定链接;
// 运行时(config)只按 type 名 LookupSession,把协议无关的输入打包成 SessionInbound 交给插件,
// 自身不出现任何协议名。

// SessionUser 是会话式入站的一个用户。运行时从顶层 users(第 4 章,BillID 计量)或口内 users 解出:
// Tag = 计量 tag;Secret = 标量口令;Fields = 复合键(如 uuid/password)。插件按自己的键取用。
type SessionUser struct {
	Tag    string
	Secret string
	Fields map[string]string
}

// SessionInbound 是构造会话式入站时运行时提供的全部输入(协议无关)。
//
// TLS 只给原始材料 + 按需构建:各协议对 tls: 块的用法不同(标准库 TLS / metacubex TLS / SSH host 私钥 /
// JLS 的 sni…),运行时不预设 —— 需要标准库服务端 TLS 的调 ServerTLS(),其余直接取 PEM / TLSNode。
type SessionInbound struct {
	Node *spec.Node // 协议自有字段(口内未声明键;插件自解)

	TLSNode   *spec.Node                  // 口内 tls: 块(sni/alpn 等;*-file 已读入);未配为空映射
	TLSCert   string                      // tls 证书 PEM(cert 内联 > cert-file);空 = 未配
	TLSKey    string                      // tls 私钥 PEM(key 内联 > key-file);空 = 未配
	ServerTLS func() (*tls.Config, error) // 按需建标准库服务端 TLS(用 TLSCert/TLSKey;二者都空 = 临时自签)

	Users []SessionUser

	Out endpoint.Outbound // 默认出站(已含路由:有 routing 块时按目标分流)

	// Dispatch 处理已握手的 TCP 流(准入 + 计量 + relay;反连 portal 时改派隧道)。
	Dispatch endpoint.StreamDispatch
	// Admit 对需要协议自管 relay 的流(如落地前须回协议信令的流)做准入 + 计量,不代管 relay。
	// 反连 portal 口为 nil:portal 流必须经 Dispatch 改派进隧道,不得在本机落地。
	Admit endpoint.AdmitHook
	// PacketDispatch 接手客户端侧多目标数据报连接(准入 + 计量 + 按包目标拆分路由;身份同 Dispatch 从 ctx 回读;
	// 反连 portal 口则整条会话桥进隧道,Bridge 侧落地)。
	PacketDispatch endpoint.PacketDispatch
}

// Runner 是自管监听的会话式入站:绑定 listen 并服务,阻塞至 ctx 取消。
type Runner interface {
	Run(ctx context.Context, listen string) error
}

// Session 是一个会话式协议插件的声明。入站有两种形态,二选一:
//   - NewInbound:自管监听(QUIC/UDP 系,自己绑 socket),返回 Runner;
//   - NewHandler:由运行时的 TCP 接入环托管监听(TLS-over-TCP 系),返回 endpoint.InboundHandler。
//
// NewOutbound 与入站可只提供其一(纯客户端或纯服务端)。
type Session struct {
	Name        string
	NewOutbound func(n *spec.Node) (endpoint.Outbound, error)
	NewInbound  func(in SessionInbound) (Runner, error)
	NewHandler  func(in SessionInbound) (endpoint.InboundHandler, error)
	// UserFromContext 回读鉴权命中的用户 tag(运行时据此把流量计入对应用户);nil = 不支持多用户计量。
	UserFromContext func(context.Context) (string, bool)
}

var sessions = map[string]Session{}

// RegisterSession 注册一个会话式协议插件(协议包 init() 调用)。重名(含与分层注册表同名)panic。
func RegisterSession(s Session) {
	if s.Name == "" || (s.NewOutbound == nil && s.NewInbound == nil && s.NewHandler == nil) {
		panic("registry: Session 缺 Name 或 NewOutbound/NewInbound/NewHandler")
	}
	if s.NewInbound != nil && s.NewHandler != nil {
		panic(fmt.Sprintf("registry: session protocol %q 的 NewInbound 与 NewHandler 只能二选一", s.Name))
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if _, dup := sessions[s.Name]; dup {
		panic(fmt.Sprintf("registry: duplicate session protocol %q", s.Name))
	}
	if _, dup := reg.m[s.Name]; dup {
		panic(fmt.Sprintf("registry: session protocol %q 与已注册的分层插件同名", s.Name))
	}
	sessions[s.Name] = s
}

// HasInbound 报该插件是否提供入站(任一形态)。
func (s Session) HasInbound() bool { return s.NewInbound != nil || s.NewHandler != nil }

// LookupSession 按 type 名查会话式协议插件。
func LookupSession(name string) (Session, bool) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	s, ok := sessions[name]
	return s, ok
}
