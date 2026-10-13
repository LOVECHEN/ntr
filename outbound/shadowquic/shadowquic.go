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

// defaultALPN 对齐 mihomo shadowquic(缺省 ["h3"])。
var defaultALPN = []string{"h3"}

// Options 是 ShadowQUIC 出站配置(auth = username/password 的 JLS PSK)。
type Options struct {
	Server   string // 上游 host:port
	Username string
	Password string
	SNI      string // JLS ServerName(缺省取 server host)
	ALPN     []string
	// UDPOverStream 选 UDP 关联模式:false = QUIC datagram(0x03,默认),true = 每目标一条单向流(0x04,无损、可超 MTU)。
	UDPOverStream bool
}

// Outbound 是 ShadowQUIC 出站:惰性建一条 JLS-over-QUIC 连接,每目标开一条 QUIC 流。
type Outbound struct {
	server   string
	tlsConf  *jlstls.Config
	quicConf *jlsquic.Config

	udpMode byte

	mu   sync.Mutex
	conn *jlsquic.Conn
	cu   *connUDP // 与 conn 同生命周期的 UDP 状态(该连接唯一的 datagram/单向流接收环)
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
	mode := cmdAssociateDatagram
	if o.UDPOverStream {
		mode = cmdAssociateStream
	}
	return &Outbound{
		server:  o.Server,
		udpMode: mode,
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

// getConn 惰性建/复用 JLS-over-QUIC 连接。连接不可用时重拨。返回该连接的 UDP 状态(同生命周期)。
func (o *Outbound) getConn(ctx context.Context) (*jlsquic.Conn, *connUDP, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.conn != nil {
		select {
		case <-o.conn.Context().Done(): // 已关闭 → 重拨
		default:
			return o.conn, o.cu, nil
		}
	}
	conn, err := jlsquic.DialAddr(ctx, o.server, o.tlsConf.Clone(), o.quicConf)
	if err != nil {
		return nil, nil, err
	}
	o.conn, o.cu = conn, newConnUDP(conn)
	return conn, o.cu, nil
}

// DialStream 在 JLS-QUIC 连接上开一条到 dst 的代理流:开流 → 写 [cmdConnect][socks5addr] → 中继。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	conn, _, err := o.getConn(ctx)
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

// DialPacket 开一个 UDP 关联:开双向流写 [cmd][0.0.0.0:0] 作控制流,返回多目标 link.PacketConn(dst 不绑定,
// 按 WritePacket 的目标逐包宣告 id 并投递)。
func (o *Outbound) DialPacket(ctx context.Context, _ addr.Socksaddr) (link.PacketConn, error) {
	conn, cu, err := o.getConn(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeAssociateRequest(stream, o.udpMode); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return newAssoc(cu, stream, o.udpMode, nil), nil
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
