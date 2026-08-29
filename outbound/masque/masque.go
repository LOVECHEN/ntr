// Package masque 把 MASQUE 接入 NTR:客户端出站 + 服务端入站。
//
// MASQUE 是 IETF 标准的 HTTP 代理族:
//   - TCP:RFC 9220 CONNECT over HTTP/3(:method=CONNECT,:authority=目标)
//   - UDP:RFC 9298 connect-udp(Extended CONNECT,:protocol=connect-udp,
//     目标编在 URI 模板 /.well-known/masque/udp/{host}/{port}/;UDP 包走 HTTP Datagram)
//
// ★零新依赖:用 NTR 已有的 metacubex/quic-go 的 http3 子包(自带 Extended CONNECT + Datagram),
// 不引入 quic-go/masque-go(那会拖进第三套 quic-go fork,违反瘦核心)。
// RFC 9297 的 Quarter-Stream-ID 由 http3 库处理;RFC 9298 的 Context-ID varint 由本包自己拼/剥。
//
// 会话式:一条 QUIC+H3 连接多路复用多条 CONNECT 流,故走 endpoint.Outbound + 自管监听的入站,
// 不套 NTR 流式栈。
package masque

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	mhttp "github.com/metacubex/http"
	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
	mtls "github.com/metacubex/tls"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = (*Outbound)(nil)

// connectUDPProto 是 RFC 9298 规定的 :protocol 值。
const connectUDPProto = "connect-udp"

// udpPayloadMax 是 RFC 9298 §5 规定的 Context-ID 0 下 UDP 载荷上限。
const udpPayloadMax = 65527

// Options 是 MASQUE 出站配置。
type Options struct {
	Server   string // 上游 host:port(QUIC/UDP)
	SNI      string
	Insecure bool
	User     string // 可选:部分部署用 HTTP Basic 保护代理
	Password string
}

// Outbound 是 MASQUE 出站:惰性建一条 QUIC+H3 连接,DialStream/DialPacket 各在其上开一条流。
type Outbound struct {
	server     string
	authority  string
	tlsConfig  *mtls.Config
	quicConfig *quic.Config
	tr         *http3.Transport
	authHeader string

	mu sync.Mutex
	pc net.PacketConn
	qc *quic.Conn
	cc *http3.ClientConn
}

// NewOutbound 构造 MASQUE 出站。
func NewOutbound(o Options) (*Outbound, error) {
	if o.Server == "" {
		return nil, errors.New("masque: server 为空")
	}
	sni := o.SNI
	if sni == "" {
		if h, _, err := net.SplitHostPort(o.Server); err == nil {
			sni = h
		}
	}
	out := &Outbound{
		server:    o.Server,
		authority: o.Server,
		tlsConfig: &mtls.Config{
			ServerName:         sni,
			InsecureSkipVerify: o.Insecure,
			NextProtos:         []string{http3.NextProtoH3},
		},
		// ★ QUIC 层必须开 datagram,否则 h3 SETTINGS 声明了也发不出(事后无法补开)。
		quicConfig: &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second},
		tr:         &http3.Transport{EnableDatagrams: true},
	}
	if o.User != "" || o.Password != "" {
		out.authHeader = basicAuth(o.User, o.Password)
	}
	return out, nil
}

// DialStream 用 RFC 9220 的 CONNECT over HTTP/3 开一条到 dst 的 TCP 隧道。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	rs, err := o.openConnect(ctx, dst, "" /* 普通 CONNECT,无 :protocol */)
	if err != nil {
		return nil, err
	}
	return &h3Stream{rs: rs}, nil
}

// DialPacket 用 RFC 9298 的 connect-udp 开一条到 dst 的 UDP 隧道(单目标,目标编在 URI 里)。
func (o *Outbound) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	rs, err := o.openConnect(ctx, dst, connectUDPProto)
	if err != nil {
		return nil, err
	}
	return newUDPConn(rs, dst), nil
}

// openConnect 在共享 H3 连接上开一条流并完成 CONNECT 握手。proto 非空 = Extended CONNECT
// (:protocol=proto,目标走 RFC 9298 URI 模板);proto 空 = 普通 CONNECT(目标走 :authority)。
// 首次失败会重建连接重试一次(H3 连接可能已 GOAWAY / QUIC 已断)。
func (o *Outbound) openConnect(ctx context.Context, dst addr.Socksaddr, proto string) (*http3.RequestStream, error) {
	rs, err := o.tryConnect(ctx, dst, proto)
	if err != nil {
		o.dropDeadConn()
		rs, err = o.tryConnect(ctx, dst, proto)
	}
	return rs, err
}

func (o *Outbound) tryConnect(ctx context.Context, dst addr.Socksaddr, proto string) (*http3.RequestStream, error) {
	cc, err := o.getConn(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := rs.SendRequestHeader(o.buildRequest(dst, proto)); err != nil {
		_ = rs.Close()
		return nil, err
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		_ = rs.Close()
		return nil, err
	}
	// RFC 9298 §3.5 / RFC 9220:成功响应码在 2xx 范围。
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = rs.Close()
		return nil, fmt.Errorf("masque: 服务端响应 %d(期望 2xx)", resp.StatusCode)
	}
	return rs, nil
}

// buildRequest 造一条 CONNECT 请求。★ :protocol 靠 http.Request.Proto 字段表达(库据此判定
// Extended CONNECT 并写出 :protocol 伪头),故必须手搓 Request、绝不能用 http.NewRequest
// (它会把 Proto 置成 "HTTP/1.1",从而退化成普通 CONNECT)。
func (o *Outbound) buildRequest(dst addr.Socksaddr, proto string) *mhttp.Request {
	hdr := mhttp.Header{}
	if o.authHeader != "" {
		hdr.Set("Proxy-Authorization", o.authHeader)
	}
	u := &neturl.URL{Scheme: "https", Host: o.authority}
	if proto == "" { // 普通 CONNECT:目标在 :authority,不带 path
		return &mhttp.Request{
			Method: mhttp.MethodConnect,
			URL:    &neturl.URL{Host: dst.String()},
			Host:   dst.String(),
			Header: hdr,
		}
	}
	// Extended CONNECT(connect-udp):目标编进 RFC 9298 URI 模板。
	hdr.Set("Capsule-Protocol", "?1") // RFC 9297 §3.4:请求流承载 Capsule Protocol
	rawPath, escPath := connectUDPPath(dst)
	u.Path = rawPath
	u.RawPath = escPath // EscapedPath() 优先用它,保证 IPv6 冒号以 %3A 发出
	return &mhttp.Request{
		Method: mhttp.MethodConnect,
		Proto:  proto, // → :protocol
		URL:    u,
		Host:   o.authority,
		Header: hdr,
	}
}

// connectUDPPath 生成 RFC 9298 §2 的 URI 模板路径,返回(未转义, 已转义)两版:
// /.well-known/masque/udp/{target_host}/{target_port}/,IPv6 字面量的冒号须 %3A 转义(§3)。
func connectUDPPath(dst addr.Socksaddr) (raw, escaped string) {
	host := dst.Fqdn
	if host == "" && dst.Addr.IsValid() {
		host = dst.Addr.String()
	}
	port := strconv.Itoa(int(dst.Port))
	const prefix = "/.well-known/masque/udp/"
	return prefix + host + "/" + port + "/",
		prefix + strings.ReplaceAll(host, ":", "%3A") + "/" + port + "/"
}

// getConn 返回复用的 H3 客户端连接,首次或已断时惰性建 QUIC + H3 并校验对端能力。
func (o *Outbound) getConn(ctx context.Context) (*http3.ClientConn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cc != nil && o.qc != nil && o.qc.Context().Err() == nil {
		return o.cc, nil
	}
	o.closeLocked()

	udpAddr, err := net.ResolveUDPAddr("udp", o.server)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	qc, err := quic.Dial(ctx, pc, udpAddr, o.tlsConfig, o.quicConfig)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	cc := o.tr.NewClientConn(qc)
	// ★ 走 OpenRequestStream 这条低层路径不会自动等 SETTINGS,必须自己等 + 校验能力,
	// 否则 Extended CONNECT / datagram 可能在对端不支持时静默失败。
	select {
	case <-cc.ReceivedSettings():
	case <-qc.Context().Done():
		_ = pc.Close()
		return nil, qc.Context().Err()
	case <-ctx.Done():
		_ = pc.Close()
		return nil, ctx.Err()
	}
	s := cc.Settings()
	if !s.EnableExtendedConnect {
		_ = qc.CloseWithError(0, "")
		_ = pc.Close()
		return nil, errors.New("masque: 服务端未启用 Extended CONNECT")
	}
	if !s.EnableDatagrams {
		_ = qc.CloseWithError(0, "")
		_ = pc.Close()
		return nil, errors.New("masque: 服务端未启用 HTTP Datagram")
	}
	o.pc, o.qc, o.cc = pc, qc, cc
	return cc, nil
}

// dropDeadConn 清掉已断的连接,使下次重建。
func (o *Outbound) dropDeadConn() {
	o.mu.Lock()
	if o.qc != nil && o.qc.Context().Err() != nil {
		o.closeLocked()
	}
	o.mu.Unlock()
}

func (o *Outbound) closeLocked() {
	if o.qc != nil {
		_ = o.qc.CloseWithError(0, "")
	}
	if o.pc != nil {
		_ = o.pc.Close()
	}
	o.pc, o.qc, o.cc = nil, nil, nil
}

// Close 关闭底层 QUIC 连接(测试/收尾用)。
func (o *Outbound) Close() error {
	o.mu.Lock()
	o.closeLocked()
	o.mu.Unlock()
	return nil
}

// ---------- UDP:RFC 9298 HTTP Datagram 编解码 ----------

// udpConn 把一条 connect-udp 流抬成单目标 link.PacketConn(目标编在 URI 里,故 dst 恒定)。
type udpConn struct {
	rs   *http3.RequestStream
	dst  addr.Socksaddr
	ctx  context.Context
	stop context.CancelFunc
}

var _ link.PacketConn = (*udpConn)(nil)

func newUDPConn(rs *http3.RequestStream, dst addr.Socksaddr) *udpConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &udpConn{rs: rs, dst: dst, ctx: ctx, stop: cancel}
}

// ReadPacket 收一个 HTTP Datagram,剥掉 RFC 9298 的 Context-ID 后把 UDP 净荷放进 b。
// 非零 Context-ID 未协商 → 按 RFC 丢弃并继续收。
func (c *udpConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	for {
		data, err := c.rs.ReceiveDatagram(c.ctx)
		if err != nil {
			return addr.Socksaddr{}, err
		}
		payload, ok := stripContextID(data)
		if !ok {
			continue // 非零 context-id / 畸形,丢弃
		}
		if len(payload) > b.Tailroom() {
			continue // 超出缓冲,丢弃而非截断发错
		}
		copy(b.ExtendTail(len(payload)), payload)
		return c.dst, nil
	}
}

// WritePacket 把 b 的 UDP 净荷前置 Context-ID 0 后作为一个 HTTP Datagram 发出。
func (c *udpConn) WritePacket(b *buf.Buffer, _ addr.Socksaddr) error {
	if b.Len() > udpPayloadMax { // RFC 9298 §5 上限
		return fmt.Errorf("masque: UDP 载荷 %d 超过上限 %d", b.Len(), udpPayloadMax)
	}
	h := b.ExtendHeader(1)
	h[0] = 0x00 // Context ID = 0(varint 单字节)= 原始 UDP 净荷
	return c.rs.SendDatagram(b.Bytes())
}

func (c *udpConn) Close() error {
	c.stop()
	return c.rs.Close()
}
func (c *udpConn) LocalAddr() net.Addr           { return masqueAddr{} }
func (c *udpConn) SetDeadline(t time.Time) error { return nil }
func (c *udpConn) Unwrap() any                   { return nil }

// stripContextID 剥掉 HTTP Datagram Payload 前的 Context-ID varint。
// 仅 Context-ID 0 有效(RFC 9298 §5:0 = 未经修改的原始 UDP 净荷)。
func stripContextID(data []byte) ([]byte, bool) {
	r := bytes.NewReader(data)
	id, err := quicvarint.Read(r)
	if err != nil || id != 0 {
		return nil, false
	}
	return data[len(data)-r.Len():], true
}

// prependContextID 在 payload 前拼 Context-ID 0(用于服务端下行,无 buf.Buffer 可复用时)。
func prependContextID(payload []byte) []byte {
	out := make([]byte, 0, 1+len(payload))
	out = quicvarint.Append(out, 0)
	return append(out, payload...)
}

// ---------- TCP:CONNECT over h3 的流适配 ----------

// h3Stream 把一条 CONNECT over h3 的请求流抬成 link.Stream。
type h3Stream struct{ rs *http3.RequestStream }

func (s *h3Stream) Read(p []byte) (int, error)     { return s.rs.Read(p) }
func (s *h3Stream) Write(p []byte) (int, error)    { return s.rs.Write(p) }
func (s *h3Stream) Close() error                   { return s.rs.Close() }
func (*h3Stream) LocalAddr() net.Addr              { return masqueAddr{} }
func (*h3Stream) RemoteAddr() net.Addr             { return masqueAddr{} }
func (*h3Stream) SetDeadline(time.Time) error      { return nil }
func (*h3Stream) SetReadDeadline(time.Time) error  { return nil }
func (*h3Stream) SetWriteDeadline(time.Time) error { return nil }
func (*h3Stream) Unwrap() any                      { return nil }

type masqueAddr struct{}

func (masqueAddr) Network() string { return "masque" }
func (masqueAddr) String() string  { return "masque-h3" }
