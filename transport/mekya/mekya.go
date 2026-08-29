package mekya

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
	"github.com/LOVECHEN/ntr/transport/mkcp"
)

var _ transport.BaseTransport = (*Transport)(nil)

// Config 是 mekya 层配置:meek 的 HTTPS path + TLS(mekya 强制 https+h2)+ 底层 KCP 参数(两端须一致)。
type Config struct {
	Path       string // meek HTTPS 路径(默认 /);服务端接受任意路径,仅客户端拼 URL 用
	SNI        string // 客户端 TLS ServerName
	Insecure   bool   // 客户端跳过证书校验(自签场景)
	CertPEM    string // 服务端证书(留空 → 自签临时证书)
	KeyPEM     string
	KCP        mkcp.KCPParams
}

// Parse 从哑节点解出 Config。KCP 缺省对齐 mkcp(MTU 1350、TTI 50、上/下 5/20、无拥塞、header none)。
func Parse(n *spec.Node) (Config, error) {
	path := n.Get("path").Str()
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	sni := n.Get("sni").Str()
	if sni == "" {
		sni = n.Get("server-name").Str()
	}
	return Config{
		Path:     path,
		SNI:      sni,
		Insecure: n.Get("insecure").Bool(),
		CertPEM:  n.Get("cert").Str(),
		KeyPEM:   n.Get("key").Str(),
		KCP: mkcp.KCPParams{
			MTU:              uint32(n.Get("mtu").Int(1350)),
			TTI:              uint32(n.Get("tti").Int(50)),
			UplinkCapacity:   uint32(n.Get("uplink-capacity").Int(5)),
			DownlinkCapacity: uint32(n.Get("downlink-capacity").Int(20)),
			Congestion:       n.Get("congestion").Bool(),
			Seed:             n.Get("seed").Str(),
			Header:           n.Get("header").Str(),
		},
	}, nil
}

// Transport 是 mekya 传输句柄。
type Transport struct{ cfg Config }

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	return &Transport{cfg: cfg}, nil
}

// DialBase 实现 BaseTransport:建 meek 客户端会话(HTTPS 轮询)→ 套 KCP → 可靠 link.Stream。
func (t *Transport) DialBase(ctx context.Context, server string) (link.Stream, error) {
	url := "https://" + server + t.cfg.Path
	sni := t.cfg.SNI
	if sni == "" {
		if h, _, err := net.SplitHostPort(server); err == nil {
			sni = h
		}
	}
	tlsConf := &tls.Config{ServerName: sni, InsecureSkipVerify: t.cfg.Insecure, NextProtos: []string{"h2", "http/1.1"}}
	remote := mekyaAddr(server)
	mc, err := newMeekClientConn(url, remote, tlsConf)
	if err != nil {
		return nil, err
	}
	kc, err := mkcp.DialKCP(ctx, mc, t.cfg.KCP)
	if err != nil {
		_ = mc.Close()
		return nil, err
	}
	return connStream{kc}, nil
}

// ListenBase 实现 BaseTransport:TCP+TLS 上起 HTTPS 服务(meek)+ 会话多路复用 packetconn + KCP accept。
func (t *Transport) ListenBase(ctx context.Context, listen string) (transport.BaseListener, error) {
	cert, err := serverCert(t.cfg.CertPEM, t.cfg.KeyPEM)
	if err != nil {
		return nil, err
	}
	rawLn, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	pc := newMeekServerPacketConn()
	// ★用 ServeTLS(把 cert 放 srv.TLSConfig)而非 Serve(手搓 tls.Listener):前者会自动 setupHTTP2,
	// 服务端才真正支持 h2。mihomo mekya 强制 h2,漏此则其请求根本到不了 handler(net/http 不自动开 h2)。
	srv := &http.Server{
		Handler:   pc,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}},
	}
	go func() { _ = srv.ServeTLS(rawLn, "", "") }()
	kcpL, err := mkcp.ListenKCP(ctx, pc, t.cfg.KCP)
	if err != nil {
		_ = srv.Close()
		_ = rawLn.Close()
		_ = pc.Close()
		return nil, err
	}
	return &mekyaListener{kcpL: kcpL, srv: srv, ln: rawLn, pc: pc}, nil
}

// mekyaListener 把 mkcpcore.Listener + HTTP 服务抬成 transport.BaseListener。
type mekyaListener struct {
	kcpL mkcp.KCPListener
	srv  *http.Server
	ln   net.Listener
	pc   *meekServerPacketConn
}

func (m *mekyaListener) Accept() (link.Stream, error) {
	c, err := m.kcpL.Accept()
	if err != nil {
		return nil, err
	}
	return connStream{c}, nil
}
func (m *mekyaListener) Close() error {
	_ = m.srv.Close()
	_ = m.kcpL.Close()
	_ = m.pc.Close()
	return m.ln.Close()
}
func (m *mekyaListener) Addr() net.Addr { return m.ln.Addr() }

// serverCert 取服务端证书:给了 CertPEM/KeyPEM 就用,否则自签临时 ECDSA P-256(dev;客户端需 insecure)。
func serverCert(certPEM, keyPEM string) (tls.Certificate, error) {
	if certPEM != "" || keyPEM != "" {
		return tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ntr-mekya"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// connStream 把 KCP net.Conn 抬成 link.Stream。
type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

var _ link.Stream = connStream{}

// 注册 mekya 传输层(Band=Base,居栈底 —— HTTP+KCP 可靠传输)。manifest blank-import 链入。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "mekya",
		Display: "mekya (KCP-over-HTTP)",
		Band:    registry.BandBase,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
