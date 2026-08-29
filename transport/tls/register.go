package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/LOVECHEN/ntr/core/cap"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// Config 是 TLS 层自有配置。服务端给 CertPEM/KeyPEM(留空 → 自签临时证书,dev/测试用);
// 客户端给 ServerName + 是否跳过校验(自签场景)。
type Config struct {
	CertPEM    string
	KeyPEM     string
	ServerName string
	Insecure   bool
	ALPN       []string
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	var alpn []string
	if s := n.Get("alpn").Str(); s != "" {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				alpn = append(alpn, p)
			}
		}
	}
	return Config{
		CertPEM:    n.Get("cert").Str(),
		KeyPEM:     n.Get("key").Str(),
		ServerName: n.Get("sni").Str(),
		Insecure:   n.Get("insecure").Bool(),
		ALPN:       alpn,
	}, nil
}

// Build 构造 Transport:定好双向 tls.Config(证书/校验策略连接级复用)。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	var cert cryptotls.Certificate
	var err error
	if cfg.CertPEM != "" || cfg.KeyPEM != "" {
		cert, err = cryptotls.X509KeyPair([]byte(cfg.CertPEM), []byte(cfg.KeyPEM))
		if err != nil {
			return nil, fmt.Errorf("tls: 证书/私钥无效:%w", err)
		}
	} else {
		cert, err = ephemeralCert() // 自签临时证书(dev);生产应配 CertPEM/KeyPEM
		if err != nil {
			return nil, err
		}
	}
	return &Transport{
		server: &cryptotls.Config{
			Certificates: []cryptotls.Certificate{cert},
			MinVersion:   cryptotls.VersionTLS12,
			NextProtos:   cfg.ALPN,
		},
		client: &cryptotls.Config{
			ServerName:         cfg.ServerName,
			InsecureSkipVerify: cfg.Insecure,
			MinVersion:         cryptotls.VersionTLS12,
			NextProtos:         cfg.ALPN,
		},
	}, nil
}

// ephemeralCert 生成一张自签 ECDSA P-256 证书(dev/测试;客户端需 insecure=true)。
func ephemeralCert() (cryptotls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return cryptotls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ntr-dev"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return cryptotls.Certificate{}, err
	}
	return cryptotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// 注册 TLS 传输层(Band=Crypto)—— manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:     "tls",
		Display:  "TLS",
		Band:     registry.BandCrypto,
		In:       []registry.Sort{registry.SortStream},
		Out:      registry.SortStream,
		Provides: []cap.ID{cap.IDSecureCarrier}, // 向上层提供 TLS 级机密性
		Reload:   registry.ReloadDrain,          // 改证书 = 只影响该单元
		Parse:    Parse,
		Build:    Build,
	})
}
