// Package endpoint 定义入站/出站的端点契约与不可变 Metadata(承设计第 2 章 §2.3)。
//
// Metadata 在 admission 边界一次性折叠成不可变归属:Source/Destination 在 accept 时定,
// sniff 在嗅探阶段定,cred 在最内层握手鉴权完成那刻锁定(pre-auth 期 = Unmatched,
// 匹配后追认一次)。冻结后全链路只读。入站与出站是同一变换器栈的两个 Mode 取值,
// Outbound 与底层 Dialer 结构同构(type alias 焊死)。
package endpoint

import (
	"context"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/link"
)

// Network 是传输网络类型。
type Network uint8

const (
	NetworkTCP Network = iota
	NetworkUDP
)

func (n Network) String() string {
	switch n {
	case NetworkTCP:
		return "tcp"
	case NetworkUDP:
		return "udp"
	default:
		return "unknown"
	}
}

// SniffProto 是嗅探识别出的应用协议(承第 10 章 §10.4.2)。
type SniffProto uint8

const (
	SniffNone SniffProto = iota
	SniffTLS             // ClientHello SNI
	SniffHTTP            // Host 头
	SniffQUIC            // QUIC Initial(第 11 章 §11.2)
	SniffSTUN            // STUN 绑定报文(WebRTC/ICE;magic cookie 0x2112A442)—— 供 protocol 规则拦截防真实 IP 泄漏
)

// String 返回协议的小写名(供 routing 的 protocol 维度按名匹配;SniffNone → "")。
func (p SniffProto) String() string {
	switch p {
	case SniffTLS:
		return "tls"
	case SniffHTTP:
		return "http"
	case SniffQUIC:
		return "quic"
	case SniffSTUN:
		return "stun"
	default:
		return ""
	}
}

// SniffFail 是嗅探失败原因(绝不静默:失败也要可见)。
type SniffFail uint8

const (
	SniffFailNone SniffFail = iota
	SniffFailNoMatch
	SniffFailTimeout
	SniffFailDisabled
)

// sniffResult 是入站嗅探产物(私有,单赋值:SetSniff 二次写 panic)。
type sniffResult struct {
	proto  SniffProto
	domain string
	fail   SniffFail
	set    bool
}

// Metadata 是一次性折叠、之后不可变的归属。cred/sniff 私有,只经受控 getter/setter。
type Metadata struct {
	Network     Network
	Source      addr.Socksaddr // 对端 socket 地址(取证标签,绝不做计费键)
	Destination addr.Socksaddr // 逻辑目标(可为域名)

	cred      cred.Ref
	credBound bool
	sniff     sniffResult
}

// CredID 返回归属凭据 ID(上报键)。
func (m *Metadata) CredID() cred.ID { return m.cred.ID }

// Cred 返回归属句柄(值拷贝;Ref 内含稳定指针,拷贝廉价)。
func (m *Metadata) Cred() cred.Ref { return m.cred }

// BindCred 绑定归属。允许 pre-auth(Unmatched)→ 鉴权完成后追认到真凭据一次;
// 鉴权完成后再次 bind 到不同凭据 panic(single-assignment 冻结于鉴权完成)。
func (m *Metadata) BindCred(r cred.Ref) {
	if m.credBound && m.cred.ID != cred.Unmatched {
		panic("endpoint: cred re-bind after auth completion")
	}
	m.cred = r
	m.credBound = true
}

// SetSniff 一次性写入嗅探结果;二次写 panic(单赋值)。
func (m *Metadata) SetSniff(proto SniffProto, domain string, fail SniffFail) {
	if m.sniff.set {
		panic("endpoint: sniff double-write")
	}
	m.sniff = sniffResult{proto: proto, domain: domain, fail: fail, set: true}
}

// SniffDomain 返回嗅探到的域名(ok=false 表示未嗅到有效域名)。
func (m *Metadata) SniffDomain() (domain string, ok bool) {
	return m.sniff.domain, m.sniff.set && m.sniff.domain != ""
}

// InboundHandler 是入站处理器:接受升级后的强类型 Stream/PacketConn + 不可变 Metadata。
// TUN 与 socket 入站复用同一接口,下游对来源无感知(承第 3 章 §3.6)。
type InboundHandler interface {
	HandleStream(ctx context.Context, s link.Stream, md *Metadata) error
	HandlePacket(ctx context.Context, p link.PacketConn, md *Metadata) error
}

// StreamDispatch 处理一条【已握手】的流(承 stream + 逻辑目标 + 网络)。会话式协议(anytls/hy1/
// hy2/tuic —— 自管监听、每流已握手含目标)用它决定每流去向:默认 relay 到出站,反连 portal 时
// 改派到隧道。nil = 走默认(relay 到出站)。此类型让会话式入站【免修改协议本身】即可接入反连
// (只在其入站接线注入一个函数),且不引 reverse/service 依赖(纯 core 契约)。
type StreamDispatch func(ctx context.Context, stream link.Stream, dst addr.Socksaddr, network Network) error

// AdmitHook 供【落地前需要协议特定信令】的会话式协议(如 hysteria v1:拨通出站后必须回
// ReportConnHandshakeSuccess 才能开始转发)做接入 + 计量包裹但【不代管 relay】:返回计量流 + release,
// 协议自行完成握手信令后 relay(计量流)。与 StreamDispatch 互补(后者代管 relay,适用无特殊落地信令的
// 协议)。同样纯 core 契约、免协议 import service:接入逻辑作为一个函数注入。nil = 不接入(旧行为)。
// 被拒(限额/停用/mem-guard)返回非 nil error 且已关 s;协议应据此放弃本流。
type AdmitHook func(ctx context.Context, s link.Stream) (link.Stream, func(), error)

// Outbound 是出站:拨到 dst、给一个传输。它以本机身份出示凭据向上游认证,不进凭据树。
type Outbound interface {
	DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error)
	DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error)
}

// Dialer 与 Outbound 结构同构 —— dial-via 链注入"另一个出站当底层拨号器"无需适配器
// (承第 8 章 §8.1.3)。
type Dialer = Outbound
