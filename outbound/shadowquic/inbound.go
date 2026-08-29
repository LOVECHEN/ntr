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

// Inbound 是 ShadowQUIC 入站:UDP 上跑 JLS-over-QUIC 监听,每条流读 [cmd][socks5addr] 后路由到出站。
type Inbound struct {
	tlsConf  *jlstls.Config
	quicConf *jlsquic.Config
	out      endpoint.Outbound
	dispatch endpoint.StreamDispatch
}

// NewInbound 构造 ShadowQUIC 入站(服务端随机证书 + JLS 用户 + 绑定出站)。sni 缺省取 dest host。
func NewInbound(users []User, sni, dest string, alpn []string, out endpoint.Outbound, dispatch endpoint.StreamDispatch) (*Inbound, error) {
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

// handleConn 在一条 QUIC 连接上循环接受流(JLS 已在握手层认证)。
func (h *Inbound) handleConn(ctx context.Context, conn *jlsquic.Conn) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go h.handleStream(ctx, conn, stream)
	}
}

// handleStream 读一条流的首段 [cmd][socks5addr],CommandConnect 即路由到出站中继。
func (h *Inbound) handleStream(ctx context.Context, conn *jlsquic.Conn, stream *jlsquic.Stream) {
	var cmd [1]byte
	if _, err := io.ReadFull(stream, cmd[:]); err != nil {
		_ = stream.Close()
		return
	}
	if cmd[0] != cmdConnect { // v1 仅 CONNECT(UDP associate 后续)
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
