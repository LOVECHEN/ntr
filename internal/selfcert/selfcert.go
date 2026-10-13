// Package selfcert 造会话式协议服务端的 TLS 配置:给了 cert/key PEM 就用,否则自签临时证书(dev)。
// 两种 TLS 栈各一个入口 —— 标准库 crypto/tls(anytls/tuic/juicity/naive/trusttunnel/hy1…)与
// metacubex/tls(hy2/masque/connect-ip 所用 quic-go fork 要它)。运行时与各插件共用,免插件互相 import。
package selfcert

import (
	"crypto"
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

	mtls "github.com/metacubex/tls"
)

// Std 造标准库服务端 TLS 配置(最低 TLS 1.2;需 1.3 的协议自行抬高)。
func Std(certPEM, keyPEM string) (*cryptotls.Config, error) {
	var cert cryptotls.Certificate
	if certPEM != "" || keyPEM != "" {
		c, err := cryptotls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("证书/私钥无效:%w", err)
		}
		cert = c
	} else {
		der, key, err := ephemeral()
		if err != nil {
			return nil, err
		}
		cert = cryptotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	return &cryptotls.Config{Certificates: []cryptotls.Certificate{cert}, MinVersion: cryptotls.VersionTLS12}, nil
}

// Metacubex 造 metacubex/tls 服务端配置(最低 TLS 1.3,QUIC 要求)。
func Metacubex(certPEM, keyPEM string) (*mtls.Config, error) {
	var cert mtls.Certificate
	if certPEM != "" || keyPEM != "" {
		c, err := mtls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("证书/私钥无效:%w", err)
		}
		cert = c
	} else {
		der, key, err := ephemeral()
		if err != nil {
			return nil, err
		}
		cert = mtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	return &mtls.Config{Certificates: []mtls.Certificate{cert}, MinVersion: mtls.VersionTLS13}, nil
}

// ephemeral 生成一张自签 P-256 证书(localhost / 127.0.0.1 / ::1,10 年)。
func ephemeral() ([]byte, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ntr"},
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
		return nil, nil, err
	}
	return der, key, nil
}
