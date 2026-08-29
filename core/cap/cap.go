// Package cap 定义层间能力接口(承设计第 2 章 §2.2)——上层经 link.GetCapability[T]
// 沿 Unwrap 链发现下层能力,零 unsafe/零 reflect(读私有字段的 unsafe 只允许出现在
// security/tls 一个包里)。IfaceOf 是 ID↔接口的单一真相源,供注册期机械绑定
// "声明 Provides ⟺ Build 产物实现接口"。
package cap

import (
	"context"
	"errors"
	"net"
	"reflect"

	"github.com/LOVECHEN/ntr/core/link"
)

// ID 是能力枚举。
type ID uint16

const (
	IDStreamConn ID = iota
	IDPacketConn
	IDTLSExporter   // ShadowTLS v3 需 ExportKeyingMaterial
	IDVisionCarrier // XTLS Vision 需已解密未消费明文 + 裸 conn
	IDCongestion    // Hysteria2 Brutal
	IDZeroRTT       // QUIC 0-RTT(预留)
	IDResettable    // SplitHTTP/XHTTP 下载流中途重连
	// IDSecureCarrier 标记「下层提供 TLS 级机密性」(tls/reality Provides)。
	// Trojan 这类「看起来像 HTTPS」的协议 Requires 它——无加密层则编译期判死,不留到运行期裸奔。
	// 这是关联表(层组合约束)的能力落点:标记能力,不进 IfaceOf(无需 Build 产物实现接口)。
	IDSecureCarrier
)

// 能力缺失 / 握手未完成的 typed error —— 上层据此大声报,绝不静默退化直连。
var (
	ErrUnsupported         = errors.New("cap: capability unsupported by lower layers")
	ErrHandshakeIncomplete = errors.New("cap: handshake not complete")
)

// CongestionAlgo 选择拥塞控制算法。
type CongestionAlgo uint8

const (
	CongestionDefault CongestionAlgo = iota
	CongestionBrutal
)

// VisionCarrier 暴露 TLS 已解密、上层尚未读走的 record 残留 + 底层裸 conn。
// XTLS Vision 消费;替代 mihomo 那套 unsafe 读私有 input/rawInput。
type VisionCarrier interface {
	HandshakeComplete() bool
	BufferedPlaintext() []byte
	RawConn() net.Conn
}

// TLSExporter 暴露 RFC5705 EKM。ShadowTLS v3 消费。
type TLSExporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// Congestion 设置拥塞算法(Hysteria2 Brutal)。
type Congestion interface {
	SetCongestion(a CongestionAlgo) error
}

// ZeroRTT 暴露 QUIC 0-RTT 拨号。
type ZeroRTT interface {
	DialEarly(ctx context.Context) (link.Session, error)
}

// Resettable 暴露"下游中途重连"通知(SplitHTTP/XHTTP 消费)。
type Resettable interface {
	OnReset(fn func())
}

// IfaceOf 是 ID↔接口的单一真相源;注册期 / CI 期机械绑定
// (Descriptor.Provides 声明的每个 ID,其 Build 产物必须实现这里映射的接口)。
var IfaceOf = map[ID]reflect.Type{
	IDTLSExporter:   reflect.TypeFor[TLSExporter](),
	IDVisionCarrier: reflect.TypeFor[VisionCarrier](),
	IDCongestion:    reflect.TypeFor[Congestion](),
	IDZeroRTT:       reflect.TypeFor[ZeroRTT](),
	IDResettable:    reflect.TypeFor[Resettable](),
}
