package anytls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// ServerTLSConfig 造 AnyTLS 服务端的 *tls.Config:给了 cert/key PEM 就用,否则自签临时证书(dev)。
func ServerTLSConfig(certPEM, keyPEM string) (*cryptotls.Config, error) {
	var cert cryptotls.Certificate
	var err error
	if certPEM != "" || keyPEM != "" {
		cert, err = cryptotls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("anytls: 证书/私钥无效:%w", err)
		}
	} else {
		cert, err = ephemeralCert()
		if err != nil {
			return nil, err
		}
	}
	return &cryptotls.Config{Certificates: []cryptotls.Certificate{cert}, MinVersion: cryptotls.VersionTLS12}, nil
}

func ephemeralCert() (cryptotls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return cryptotls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ntr-anytls"},
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
