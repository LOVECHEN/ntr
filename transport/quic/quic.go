// Package quic 实现 V2Ray QUIC 独立传输(sing-box transport/v2rayquic;core/transport.BaseTransport)。
//
// QUIC(内建 TLS 1.3)提供可靠有序多流,其上叠代理(vless 等)。是 UDP-base 传输:出站拨 UDP+QUIC 后
// OpenStream;入站 UDP 监听 QUIC,每 conn 可多流,逐流交正常代理栈。与 sing-box v2rayquic 线级互通
// (ALPN "h3",裸 QUIC 流)。xray 已移除 QUIC(v24.9.7)、mihomo 无独立 QUIC 传输,故仅 sing-box 可验。
//
// 复用 NTR 已有的 metacubex/quic-go + metacubex/tls(同 hy2/tuic)。占 BandBase,叠法 [quic, vless]。
package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	mquic "github.com/metacubex/quic-go"
	mtls "github.com/metacubex/tls"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
)

var _ transport.BaseTransport = (*Transport)(nil)

const defaultALPN = "h3" // sing-box v2rayquic 默认 ALPN

// Config 是 QUIC 传输配置。客户端 SNI+Insecure;服务端 CertPEM/KeyPEM(留空 → 自签,dev/测试)。ALPN 默认 h3。
type Config struct {
	SNI      string
	Insecure bool
	CertPEM  string
	KeyPEM   string
	ALPN     string
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	return Config{
		SNI:      n.Get("sni").Str(),
		Insecure: n.Get("insecure").Bool(),
		CertPEM:  fileOrStr(n, "cert"),
		KeyPEM:   fileOrStr(n, "key"),
		ALPN:     n.Get("alpn").Str(),
	}, nil
}

func fileOrStr(n *spec.Node, k string) string { return n.Get(k).Str() }

// Transport 是 QUIC 传输句柄。
type Transport struct {
	sni      string
	insecure bool
	alpn     string
	cert     *mtls.Certificate // 服务端证书(nil → ListenBase 时自签)
	certErr  error
}

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	alpn := cfg.ALPN
	if alpn == "" {
		alpn = defaultALPN
	}
	t := &Transport{sni: cfg.SNI, insecure: cfg.Insecure, alpn: alpn}
	if cfg.CertPEM != "" && cfg.KeyPEM != "" {
		c, err := mtls.X509KeyPair([]byte(cfg.CertPEM), []byte(cfg.KeyPEM))
		if err != nil {
			return nil, fmt.Errorf("quic: 证书:%w", err)
		}
		t.cert = &c
	}
	return t, nil
}

// DialBase 实现 BaseTransport:拨 UDP + QUIC(mtls),OpenStream,返回一条可靠 link.Stream。
func (t *Transport) DialBase(ctx context.Context, server string) (link.Stream, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	tlsCfg := &mtls.Config{ServerName: t.sni, InsecureSkipVerify: t.insecure, NextProtos: []string{t.alpn}}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = udpAddr.IP.String()
	}
	conn, err := mquic.Dial(ctx, pc, udpAddr, tlsCfg, &mquic.Config{MaxIdleTimeout: 60 * time.Second, KeepAlivePeriod: 15 * time.Second})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		_ = pc.Close()
		return nil, err
	}
	return &streamConn{st: st, conn: conn, pc: pc}, nil
}

// ListenBase 实现 BaseTransport:UDP 监听 QUIC,后台 accept conn→accept stream,每流入 accept 通道。
func (t *Transport) ListenBase(ctx context.Context, listen string) (transport.BaseListener, error) {
	cert := t.cert
	if cert == nil {
		c, err := selfSigned()
		if err != nil {
			return nil, fmt.Errorf("quic: 自签证书:%w", err)
		}
		cert = &c
	}
	udpAddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	tlsCfg := &mtls.Config{Certificates: []mtls.Certificate{*cert}, NextProtos: []string{t.alpn}}
	ln, err := mquic.Listen(pc, tlsCfg, &mquic.Config{MaxIdleTimeout: 60 * time.Second})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	l := &quicListener{ln: ln, pc: pc, ch: make(chan link.Stream, 16), done: make(chan struct{})}
	go l.acceptLoop()
	return l, nil
}

// quicListener 多路展平:每个 QUIC conn 的多条流都平摊进 ch,由 Accept 逐一取出交正常代理栈。
type quicListener struct {
	ln   *mquic.Listener
	pc   net.PacketConn
	ch   chan link.Stream
	done chan struct{}
}

func (l *quicListener) acceptLoop() {
	for {
		conn, err := l.ln.Accept(context.Background())
		if err != nil {
			return
		}
		go l.acceptStreams(conn)
	}
}

func (l *quicListener) acceptStreams(conn *mquic.Conn) {
	for {
		st, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		select {
		case l.ch <- &streamConn{st: st, conn: conn}:
		case <-l.done:
			return
		}
	}
}

func (l *quicListener) Accept() (link.Stream, error) {
	select {
	case s := <-l.ch:
		return s, nil
	case <-l.done:
		return nil, errors.New("quic: listener closed")
	}
}
func (l *quicListener) Close() error {
	close(l.done)
	_ = l.ln.Close()
	return l.pc.Close()
}
func (l *quicListener) Addr() net.Addr { return l.pc.LocalAddr() }

// streamConn 把 QUIC 流(*Stream)抬成 link.Stream:Read/Write/Close/Deadline 走流,Local/Remote 走 conn。
type streamConn struct {
	st   *mquic.Stream
	conn *mquic.Conn
	pc   net.PacketConn // 客户端侧持有底层 UDP socket(Close 时一并关);服务端侧 nil
}

var _ link.Stream = (*streamConn)(nil)

func (c *streamConn) Read(p []byte) (int, error)  { return c.st.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.st.Write(p) }
func (c *streamConn) Close() error {
	err := c.st.Close()
	if c.pc != nil { // 客户端:关流后关 QUIC conn + UDP socket
		_ = c.conn.CloseWithError(0, "")
		_ = c.pc.Close()
	}
	return err
}
func (c *streamConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *streamConn) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }
func (c *streamConn) Unwrap() any                        { return nil }

// selfSigned 生成自签 ECDSA P-256 证书(dev/测试;客户端需 insecure=true)。
func selfSigned() (mtls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return mtls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "quic"},
		NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return mtls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return mtls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return mtls.X509KeyPair(certPEM, keyPEM)
}
