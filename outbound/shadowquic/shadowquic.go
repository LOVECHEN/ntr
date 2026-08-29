package shadowquic

import (
	"context"
	"errors"
	"net"
	"sync"

	jlsquic "github.com/metacubex/jls-quic-go"
	jlstls "github.com/metacubex/jls-tls"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = (*Outbound)(nil)

var errUDPNotReady = errors.New("shadowquic: UDP over QUIC 待接入(v1 仅 TCP CONNECT)")

// defaultALPN 对齐 mihomo shadowquic(缺省 ["h3"])。
var defaultALPN = []string{"h3"}

// Options 是 ShadowQUIC 出站配置(auth = username/password 的 JLS PSK)。
type Options struct {
	Server   string // 上游 host:port
	Username string
	Password string
	SNI      string // JLS ServerName(缺省取 server host)
	ALPN     []string
}

// Outbound 是 ShadowQUIC 出站:惰性建一条 JLS-over-QUIC 连接,每目标开一条 QUIC 流。
type Outbound struct {
	server   string
	tlsConf  *jlstls.Config
	quicConf *jlsquic.Config

	mu   sync.Mutex
	conn *jlsquic.Conn
}

// NewOutbound 构造 ShadowQUIC 出站。
func NewOutbound(o Options) (*Outbound, error) {
	if o.Username == "" || o.Password == "" {
		return nil, errors.New("shadowquic: username/password 必填(JLS PSK)")
	}
	sni := o.SNI
	if sni == "" {
		if h, _, err := net.SplitHostPort(o.Server); err == nil {
			sni = h
		}
	}
	alpn := o.ALPN
	if alpn == nil {
		alpn = defaultALPN
	}
	return &Outbound{
		server: o.Server,
		tlsConf: &jlstls.Config{
			ServerName: sni,
			NextProtos: append([]string(nil), alpn...),
			JLSConfig:  &jlstls.JLSConfig{Enable: true, User: jlstls.JLSUser{Username: o.Username, Password: o.Password}},
		},
		quicConf: &jlsquic.Config{
			Versions:              []jlsquic.Version{jlsquic.Version1},
			EnableDatagrams:       true,
			MaxIncomingStreams:    1 << 16,
			MaxIncomingUniStreams: 1 << 16,
		},
	}, nil
}

// getConn 惰性建/复用 JLS-over-QUIC 连接。连接不可用时重拨。
func (o *Outbound) getConn(ctx context.Context) (*jlsquic.Conn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.conn != nil {
		select {
		case <-o.conn.Context().Done(): // 已关闭 → 重拨
		default:
			return o.conn, nil
		}
	}
	conn, err := jlsquic.DialAddr(ctx, o.server, o.tlsConf.Clone(), o.quicConf)
	if err != nil {
		return nil, err
	}
	o.conn = conn
	return conn, nil
}

// DialStream 在 JLS-QUIC 连接上开一条到 dst 的代理流:开流 → 写 [cmdConnect][socks5addr] → 中继。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	conn, err := o.getConn(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeConnectRequest(stream, dst); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return &streamConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
}

// DialPacket:ShadowQUIC UDP over QUIC 待接入(v1 仅 TCP)。
func (o *Outbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, errUDPNotReady
}

// streamConn 把一条 QUIC 双向流 + 连接端地址抬成 net.Conn / link.Stream。
type streamConn struct {
	*jlsquic.Stream
	local  net.Addr
	remote net.Addr
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }
func (s *streamConn) Unwrap() any          { return nil }
