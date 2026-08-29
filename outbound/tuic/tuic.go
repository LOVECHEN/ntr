// Package tuic 把 TUIC(v5)接入 NTR:QUIC 之上的客户端出站 + 服务端入站。
//
// ★用第三方权威实现 github.com/sagernet/sing-quic/tuic(与 mihomo/sing-box 互通)。TUIC 跑在
// QUIC 上,会话式:客户端 DialConn 开流,服务端 Service.Start 在 UDP socket 上接受 + 鉴权
// (UUID+password)+ 解复用。走 endpoint.Outbound + 自管 UDP 的入站 Runner。
package tuic

import (
	"context"
	cryptotls "crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	stuic "github.com/sagernet/sing-quic/tuic"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = (*Outbound)(nil)

var errUDPNotReady = errors.New("tuic: UDP over QUIC not implemented yet")

// Options 是 TUIC 出站配置(auth = UUID + Password)。
type Options struct {
	Server            string
	UUID              string
	Password          string
	SNI               string
	Insecure          bool
	CongestionControl string // bbr(默认)/ cubic / new_reno
}

// Outbound 是 TUIC 出站。
type Outbound struct {
	client *stuic.Client
}

// NewOutbound 构造 TUIC 出站。
func NewOutbound(o Options) (*Outbound, error) {
	uuid, err := parseUUID(o.UUID)
	if err != nil {
		return nil, err
	}
	cc := o.CongestionControl
	if cc == "" {
		cc = "bbr"
	}
	client, err := stuic.NewClient(stuic.ClientOptions{
		Context:           context.Background(),
		Dialer:            N.SystemDialer,
		ServerAddress:     M.ParseSocksaddr(o.Server),
		TLSConfig:         &clientTLS{config: &cryptotls.Config{ServerName: o.SNI, InsecureSkipVerify: o.Insecure, NextProtos: []string{"h3"}}},
		UUID:              uuid,
		Password:          o.Password,
		CongestionControl: cc,
		Heartbeat:         10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{client: client}, nil
}

// DialStream 在 TUIC QUIC 连接上开一条到 dst 的代理流。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	conn, err := o.client.DialConn(ctx, toSing(dst))
	if err != nil {
		return nil, err
	}
	return connStream{conn}, nil
}

// DialPacket:TUIC UDP over QUIC 待接入。
func (o *Outbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, errUDPNotReady
}

func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil {
		return u, err
	}
	if len(b) != 16 {
		return u, fmt.Errorf("tuic: uuid 需 16 字节,得到 %d", len(b))
	}
	copy(u[:], b)
	return u, nil
}

func toSing(a addr.Socksaddr) M.Socksaddr {
	return M.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}
func toNTR(a M.Socksaddr) addr.Socksaddr {
	return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}

type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

// NeedHandshake 转发底层 tuic clientConn 的懒发送状态:其目标 header 首次 Write 才 flush。
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
