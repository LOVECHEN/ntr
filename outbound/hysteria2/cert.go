package hysteria2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	mtls "github.com/metacubex/tls"
)

// ServerTLSConfig 造 hy2 服务端的 *metacubex-tls.Config:给了 PEM 用之,否则自签临时证书(dev)。
func ServerTLSConfig(certPEM, keyPEM string) (*mtls.Config, error) {
	if certPEM != "" || keyPEM != "" {
		cert, err := mtls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("hysteria2: 证书/私钥无效:%w", err)
		}
		return &mtls.Config{Certificates: []mtls.Certificate{cert}, MinVersion: mtls.VersionTLS13}, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ntr-hy2"},
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
		return nil, err
	}
	return &mtls.Config{
		Certificates: []mtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   mtls.VersionTLS13,
	}, nil
}
