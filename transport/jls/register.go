package jls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	jlstls "github.com/metacubex/jls-tls"

	"github.com/LOVECHEN/ntr/core/cap"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// defaultALPN 对齐 mihomo transport/jls 的 DefaultALPN(缺省 ALPN 影响握手,须一致)。
var defaultALPN = []string{"h2", "http/1.1"}

// Config 是 JLS 层配置。username/password 是双端共享 PSK(认证);sni 是握手 ServerName;
// dest 是服务端回落目标(v1 仅用于缺省 sni;回落 relay 为后续);alpn 缺省 [h2, http/1.1]。
type Config struct {
	ServerName string
	Username   string
	Password   string
	Dest       string // 服务端回落 dest(host:port);sni 为空时取其 host
	ALPN       []string
}

// Parse 从哑节点解出 Config。sni/server-name 二选一;dest 供服务端(缺省 sni)。
func Parse(n *spec.Node) (Config, error) {
	sni := n.Get("sni").Str()
	if sni == "" {
		sni = n.Get("server-name").Str()
	}
	var alpn []string
	if s := n.Get("alpn").Str(); s != "" {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				alpn = append(alpn, p)
			}
		}
	}
	return Config{
		ServerName: sni,
		Username:   n.Get("username").Str(),
		Password:   n.Get("password").Str(),
		Dest:       n.Get("dest").Str(),
		ALPN:       alpn,
	}, nil
}

// Build 构造 Transport:双向 *jlstls.Config(客户端带 User PSK;服务端带 Users PSK + 随机证书,
// JLS 靠 PSK 认证故证书只承载握手、可随机自签)。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	if cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("jls: username/password 必填(双端共享 PSK)")
	}
	sni := cfg.ServerName
	if sni == "" && cfg.Dest != "" {
		if h, _, err := net.SplitHostPort(cfg.Dest); err == nil {
			sni = h
		}
	}
	alpn := cfg.ALPN
	if alpn == nil {
		alpn = defaultALPN
	}
	user := jlstls.JLSUser{Username: cfg.Username, Password: cfg.Password}

	cert, err := ephemeralCert()
	if err != nil {
		return nil, err
	}
	return &Transport{
		client: &jlstls.Config{
			ServerName: sni,
			NextProtos: append([]string(nil), alpn...),
			JLSConfig:  &jlstls.JLSConfig{Enable: true, User: user},
		},
		server: &jlstls.Config{
			Certificates: []jlstls.Certificate{cert},
			NextProtos:   append([]string(nil), alpn...),
			MinVersion:   jlstls.VersionTLS13,
			JLSConfig:    &jlstls.JLSConfig{Enable: true, Users: []jlstls.JLSUser{user}, ServerName: sni},
		},
	}, nil
}

// ephemeralCert 生成一张随机自签 ECDSA P-256 证书(JLS 靠 PSK 认证,证书仅承载 TLS 握手,可随机)。
func ephemeralCert() (jlstls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return jlstls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ntr-jls"},
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

// 注册 JLS 传输层(Band=Crypto)—— manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:     "jls",
		Display:  "JLS",
		Band:     registry.BandCrypto,
		In:       []registry.Sort{registry.SortStream},
		Out:      registry.SortStream,
		Provides: []cap.ID{cap.IDSecureCarrier}, // JLS 提供 TLS 级机密性 + PSK 认证
		Reload:   registry.ReloadDrain,
		Parse:    Parse,
		Build:    Build,
	})
}
