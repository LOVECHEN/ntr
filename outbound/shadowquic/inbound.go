package shadowquic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"time"

	jlsquic "github.com/metacubex/jls-quic-go"
	jlstls "github.com/metacubex/jls-tls"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/relay"
)

// User 是 ShadowQUIC 服务端用户(JLS PSK)。
type User struct {
	Username string
	Password string
}

type ctxUserKey struct{}

// withUser 把 JLS 认证到的计费用户名挂进 ctx(ConnectionState().TLS.JLS.User)。
func withUser(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, ctxUserKey{}, name)
}

// UserFromContext 读认证命中的计费用户名(供 config 的 SessionDispatch 回读 → cred.ID 计量)。
func UserFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(ctxUserKey{}).(string)
	return name, ok && name != ""
}

// Inbound 是 ShadowQUIC 入站:UDP 上跑 JLS-over-QUIC 监听,每条流读 [cmd][socks5addr] 后路由到出站。
type Inbound struct {
	tlsConf  *jlstls.Config
	quicConf *jlsquic.Config
	out      endpoint.Outbound
	dispatch endpoint.StreamDispatch
	packet   endpoint.PacketDispatch
}

// NewInbound 构造 ShadowQUIC 入站(服务端随机证书 + JLS 用户 + 绑定出站)。sni 缺省取 dest host。
// packet 接手 UDP 关联(运行时准入计量 + 路由;portal 口桥进隧道);nil = 拒 UDP 关联。
func NewInbound(users []User, sni, dest string, alpn []string, out endpoint.Outbound, dispatch endpoint.StreamDispatch, packet endpoint.PacketDispatch) (*Inbound, error) {
	if len(users) == 0 {
		return nil, errors.New("shadowquic: 至少一个用户")
	}
	if sni == "" && dest != "" {
		if h, _, err := net.SplitHostPort(dest); err == nil {
			sni = h
		}
	}
	if alpn == nil {
		alpn = defaultALPN
	}
	jusers := make([]jlstls.JLSUser, 0, len(users))
	for _, u := range users {
		if u.Username == "" || u.Password == "" {
			return nil, errors.New("shadowquic: username/password 必填")
		}
		jusers = append(jusers, jlstls.JLSUser{Username: u.Username, Password: u.Password})
	}
	cert, err := ephemeralCert()
	if err != nil {
		return nil, err
	}
	return &Inbound{
		tlsConf: &jlstls.Config{
			Certificates: []jlstls.Certificate{cert},
			NextProtos:   append([]string(nil), alpn...),
			MinVersion:   jlstls.VersionTLS13,
			JLSConfig:    &jlstls.JLSConfig{Enable: true, Users: jusers, ServerName: sni},
		},
		quicConf: &jlsquic.Config{
			Versions:              []jlsquic.Version{jlsquic.Version1},
			EnableDatagrams:       true,
			MaxIncomingStreams:    1 << 16,
			MaxIncomingUniStreams: 1 << 16,
			MaxIdleTimeout:        30 * time.Second,
		},
		out:      out,
		dispatch: dispatch,
		packet:   packet,
	}, nil
}

// Run 绑定 UDP 监听并跑 QUIC accept 环,阻塞至 ctx 取消。
func (h *Inbound) Run(ctx context.Context, listenAddr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer pc.Close()
	ln, err := jlsquic.Listen(pc, h.tlsConf, h.quicConf)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go h.handleConn(ctx, conn)
	}
}

// handleConn 在一条 QUIC 连接上循环接受流(JLS 已在握手层认证)。JLS 每连接认证一次,
// 从 ConnectionState 取认证到的计费用户名挂进 ctx(该连接所有流共享,供 dispatch 计量回读)。
func (h *Inbound) handleConn(ctx context.Context, conn *jlsquic.Conn) {
	if name := conn.ConnectionState().TLS.JLS.User; name != "" {
		ctx = withUser(ctx, name)
	}
	var cu *connUDP
	if h.packet != nil { // UDP 状态随连接建(datagram/单向流接收环每连接唯一;控制与数据到达顺序不保证)
		cu = newConnUDP(conn)
	}
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go h.handleStream(ctx, conn, cu, stream)
	}
}

// handleStream 读一条流的首段 [cmd][socks5addr]:CONNECT 路由到出站中继;ASSOCIATE 起 UDP 关联交 PacketDispatch。
func (h *Inbound) handleStream(ctx context.Context, conn *jlsquic.Conn, cu *connUDP, stream *jlsquic.Stream) {
	var cmd [1]byte
	if _, err := io.ReadFull(stream, cmd[:]); err != nil {
		_ = stream.Close()
		return
	}
	switch cmd[0] {
	case cmdConnect:
	case cmdAssociateDatagram, cmdAssociateStream:
		if _, err := readSocksAddr(stream); err != nil || cu == nil { // 关联请求地址无意义(客户端写 0.0.0.0:0)
			stream.CancelRead(0)
			_ = stream.Close()
			return
		}
		_ = h.packet(ctx, newAssoc(cu, stream, cmd[0], conn.RemoteAddr())) // 返回时关联已关
		return
	default:
		stream.CancelRead(0)
		_ = stream.Close()
		return
	}
	dst, err := readSocksAddr(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	sc := &streamConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
	if h.dispatch != nil { // 反连 portal:已握手流交隧道派发
		_ = h.dispatch(ctx, sc, dst, endpoint.NetworkTCP)
		return
	}
	up, err := h.out.DialStream(ctx, dst)
	if err != nil {
		_ = sc.Close()
		return
	}
	_ = relay.Relay(sc, up)
}

// ephemeralCert 生成随机自签 P-256 证书(JLS 靠 PSK 认证,证书仅承载握手)。
func ephemeralCert() (jlstls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return jlstls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ntr-shadowquic"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return jlstls.Certificate{}, err
	}
	return jlstls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
