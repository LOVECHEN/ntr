package vless

import (
	"errors"
	"io"
	"net"

	singvless "github.com/metacubex/sing-vmess/vless"
	"github.com/metacubex/sing/common/logger"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

// flowVision 是 VLESS 唯一支持的 flow(XTLS Vision:握手后按 TLS 记录边界 splice + 抗探测 padding)。
const flowVision = "xtls-rprx-vision"

// ★Vision 用第三方权威实现 metacubex/sing-vmess 的 vless 子包(NewVisionConn 做字节精确的
// padding/splice,与 Xray / mihomo / sing-box 互通)。Vision 需反射进下层 *tls.Conn 按记录做
// splice —— NTR 严格分层只给 link.Stream,故经 link.TLSConnCarrier 能力发现取底层 TLS 连接
// (tls/reality 的 stream 实现了它),vless 零跨层 import。sing-vmess init() 自动注册 *crypto/tls.Conn。

// encodeFlowAddon 把 flow 编成 VLESS addon(protobuf Addons{flow=field 1 string}:0x0A <len> <flow>)。
func encodeFlowAddon(flow string) []byte {
	out := make([]byte, 0, 2+len(flow))
	out = append(out, 0x0A, byte(len(flow)))
	return append(out, flow...)
}

// parseFlowAddon 从 addon 原始字节解出 flow(仅认 field 1 LEN string;其余忽略)。
func parseFlowAddon(addons []byte) string {
	if len(addons) >= 2 && addons[0] == 0x0A {
		l := int(addons[1])
		if 2+l <= len(addons) {
			return string(addons[2 : 2+l])
		}
	}
	return ""
}

// clientVision:客户端 Vision 握手 —— 惰性写请求头(含 flow addon)+ VisionConn 包裹。
func clientVision(below link.Stream, uuid [16]byte, dst addr.Socksaddr) (link.Stream, error) {
	carrier, ok := below.(link.TLSConnCarrier) // 直接断言紧邻下层,不遍历 Unwrap 链 —— 强制 vision 紧邻 tls/reality
	if !ok {
		return nil, errors.New("vless vision: 紧邻下层非 TLS(Vision 必须直接叠在 tls/reality 上,中间不能有 ws/grpc 等)")
	}
	lazy := &lazyClientStream{Stream: below, uuid: uuid, dst: dst, addons: encodeFlowAddon(flowVision)}
	vc, err := singvless.NewVisionConn(lazy, carrier.TLSConn(), uuid, logger.NOP())
	if err != nil {
		return nil, err
	}
	return &visionStream{Conn: vc, below: below}, nil
}

// serverVision:服务端 Vision —— serverStream(惰性响应头)+ VisionConn 包裹。请求头已由外部读掉。
func serverVision(below link.Stream, uuid [16]byte) (link.Stream, error) {
	carrier, ok := below.(link.TLSConnCarrier) // 直接断言紧邻下层,不遍历 Unwrap 链 —— 强制 vision 紧邻 tls/reality
	if !ok {
		return nil, errors.New("vless vision: 紧邻下层非 TLS(Vision 必须直接叠在 tls/reality 上,中间不能有 ws/grpc 等)")
	}
	ss := &serverStream{Stream: below}
	vc, err := singvless.NewVisionConn(ss, carrier.TLSConn(), uuid, logger.NOP())
	if err != nil {
		return nil, err
	}
	return &visionStream{Conn: vc, below: below}, nil
}

// visionStream 把 sing-vmess VisionConn(net.Conn)抬成 link.Stream。
type visionStream struct {
	net.Conn
	below link.Stream
}

func (s *visionStream) Unwrap() any { return s.below }

// lazyClientStream:Vision 客户端流 —— 首次写前置 VLESS 请求头(带 flow addon),首次读剥响应头。
// 惰性(不像非 Vision 路径 ClientHandshake 里 eager 写头):VisionConn 在其首次写时触发本流写头,
// 与 sing-vmess remoteConn 语义一致,保证 [vless 头][vision padding 数据] 的线序被 Vision 正确接管。
type lazyClientStream struct {
	link.Stream
	uuid         [16]byte
	dst          addr.Socksaddr
	addons       []byte
	wroteHdr     bool
	strippedResp bool
}

func (s *lazyClientStream) Write(p []byte) (int, error) {
	if s.wroteHdr {
		return s.Stream.Write(p)
	}
	s.wroteHdr = true
	b := buf.New()
	defer b.Release()
	if err := (RequestCodec{}).Encode(b, RequestHeader{UUID: s.uuid, Addons: s.addons, Command: CmdTCP, Dst: s.dst}); err != nil {
		return 0, err
	}
	if _, err := b.Write(p); err != nil {
		return 0, err
	}
	if _, err := s.Stream.Write(b.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *lazyClientStream) Read(p []byte) (int, error) {
	if !s.strippedResp {
		s.strippedResp = true
		var vh [2]byte // version(1) + addonLen(1)
		if _, err := io.ReadFull(s.Stream, vh[:]); err != nil {
			return 0, err
		}
		if vh[0] != Version {
			return 0, ErrVersion
		}
		if alen := int(vh[1]); alen > 0 {
			if _, err := io.ReadFull(s.Stream, make([]byte, alen)); err != nil {
				return 0, err
			}
		}
	}
	return s.Stream.Read(p)
}

func (s *lazyClientStream) Unwrap() any { return s.Stream }
