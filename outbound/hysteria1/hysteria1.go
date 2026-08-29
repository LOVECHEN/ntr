// Package hysteria1 把 Hysteria(v1)接入 NTR:QUIC 之上的客户端出站 + 服务端入站。
//
// ★用第三方权威实现 github.com/sagernet/sing-quic/hysteria(与 mihomo/sing-box 互通)。
// Hysteria v1 会话式:客户端 DialConn 开流,服务端 Service.Start 在 UDP socket 上接受 +
// 鉴权(password,可选 salamander 混淆)+ 解复用。用固定带宽(Brutal 拥塞控制,故需 up/down)。
// 走 endpoint.Outbound + 自管 UDP 的入站 Runner(同 TUIC/Hysteria2 模型)。
package hysteria1

import (
	"context"
	cryptotls "crypto/tls"
	"errors"
	"net"
	"time"

	shysteria "github.com/sagernet/sing-quic/hysteria"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = (*Outbound)(nil)

var errUDPNotReady = errors.New("hysteria1: UDP over QUIC not implemented yet")

// defaultMbps 是缺省上下行带宽(Brutal 拥塞控制需要一个值;仅影响限速,不影响互通)。
const defaultMbps = 100

// mbpsToBPS 把 Mbps 转成字节/秒(hysteria 内部单位)。
func mbpsToBPS(mbps uint64) uint64 { return mbps * 1000 * 1000 / 8 }

// Options 是 Hysteria v1 出站配置(auth = Password;Obfs = salamander 混淆口令,可空)。
type Options struct {
	Server   string
	Password string
	Obfs     string
	SNI      string
	Insecure bool
	UpMbps   uint64
	DownMbps uint64
}

// Outbound 是 Hysteria v1 出站。
type Outbound struct {
	client *shysteria.Client
}

// NewOutbound 构造 Hysteria v1 出站。
func NewOutbound(o Options) (*Outbound, error) {
	up, down := o.UpMbps, o.DownMbps
	if up == 0 {
		up = defaultMbps
	}
	if down == 0 {
		down = defaultMbps
	}
	client, err := shysteria.NewClient(shysteria.ClientOptions{
		Context:       context.Background(),
		Dialer:        N.SystemDialer,
		ServerAddress: M.ParseSocksaddr(o.Server),
		SendBPS:       mbpsToBPS(up),
		ReceiveBPS:    mbpsToBPS(down),
		XPlusPassword: o.Obfs,
		Password:      o.Password,
		TLSConfig:     &clientTLS{config: &cryptotls.Config{ServerName: o.SNI, InsecureSkipVerify: o.Insecure, NextProtos: []string{"hysteria"}}},
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{client: client}, nil
}

// DialStream 在 Hysteria QUIC 连接上开一条到 dst 的代理流。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	conn, err := o.client.DialConn(ctx, toSing(dst))
	if err != nil {
		return nil, err
	}
	return connStream{conn}, nil
}

// DialPacket:Hysteria UDP over QUIC 待接入。
func (o *Outbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, errUDPNotReady
}

func toSing(a addr.Socksaddr) M.Socksaddr {
	return M.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}
func toNTR(a M.Socksaddr) addr.Socksaddr {
	return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}

type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

// NeedHandshake 转发底层 hysteria v1 clientConn 的懒发送状态:其目标 header 首次 Write 才 flush。
// 反连 Bridge 据此在跑 muxcool ServerWorker(先读不写)前主动 flush,避免与 Portal 互等死锁。
func (c connStream) NeedHandshake() bool {
	if h, ok := c.Conn.(interface{ NeedHandshake() bool }); ok {
		return h.NeedHandshake()
	}
	return false
}

// ---------- aTLS 适配:crypto/tls.Config → sagernet aTLS.Config / ServerConfig ----------

type clientTLS struct{ config *cryptotls.Config }

func (c *clientTLS) ServerName() string                    { return c.config.ServerName }
func (c *clientTLS) SetServerName(s string)                { c.config.ServerName = s }
func (c *clientTLS) NextProtos() []string                  { return c.config.NextProtos }
func (c *clientTLS) SetNextProtos(n []string)              { c.config.NextProtos = n }
func (c *clientTLS) HandshakeTimeout() time.Duration       { return 0 }
func (c *clientTLS) SetHandshakeTimeout(time.Duration)     {}
func (c *clientTLS) STDConfig() (*cryptotls.Config, error) { return c.config, nil }
func (c *clientTLS) Client(conn net.Conn) (aTLS.Conn, error) {
	return cryptotls.Client(conn, c.config), nil
}
func (c *clientTLS) Clone() aTLS.Config { return &clientTLS{config: c.config.Clone()} }

type serverTLS struct{ config *cryptotls.Config }

func (s *serverTLS) ServerName() string                    { return s.config.ServerName }
func (s *serverTLS) SetServerName(n string)                { s.config.ServerName = n }
func (s *serverTLS) NextProtos() []string                  { return s.config.NextProtos }
func (s *serverTLS) SetNextProtos(n []string)              { s.config.NextProtos = n }
func (s *serverTLS) HandshakeTimeout() time.Duration       { return 0 }
func (s *serverTLS) SetHandshakeTimeout(time.Duration)     {}
func (s *serverTLS) STDConfig() (*cryptotls.Config, error) { return s.config, nil }
func (s *serverTLS) Client(conn net.Conn) (aTLS.Conn, error) {
	return cryptotls.Client(conn, s.config), nil
}
func (s *serverTLS) Clone() aTLS.Config { return &serverTLS{config: s.config.Clone()} }
func (s *serverTLS) Start() error       { return nil }
func (s *serverTLS) Close() error       { return nil }
func (s *serverTLS) Server(conn net.Conn) (aTLS.Conn, error) {
	return cryptotls.Server(conn, s.config), nil
}
