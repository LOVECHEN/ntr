// 诱骗后端:TLS1.3 服务器,握手后回一个极简 HTTP 响应并保活(供 tlsmirror 镜像)。
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	// DECOY_TLS12=1 → 只允许 TLS1.2(强制载体走 TLS1.2 显式 nonce GCM 套件,供 tlsmirror 显式 nonce 交叉验证)。
	minV := uint16(tls.VersionTLS13)
	maxV := uint16(tls.VersionTLS13)
	if os.Getenv("DECOY_TLS12") == "1" {
		minV, maxV = tls.VersionTLS12, tls.VersionTLS12
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "decoy.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(87600 * time.Hour),
		DNSNames:     []string{"decoy.example.com", "localhost"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: minV, MaxVersion: maxV, NextProtos: []string{"h2", "http/1.1"}}
	if os.Getenv("DECOY_TLS12") == "1" {
		// 只提供 AES-128-GCM(TLS1.2 里唯一带 8B 显式 nonce 的族;CHACHA20 无显式 nonce,会触发镜像回退)。
		cfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	}
	ln, err := tls.Listen("tcp", "0.0.0.0:443", cfg)
	if err != nil { panic(err) }
	for {
		c, err := ln.Accept()
		if err != nil { continue }
		go func(c net.Conn) {
			defer c.Close()
			// 保活:读并丢弃,握手后不主动关(tlsmirror 需要稳定的载体会话)。
			_, _ = io.Copy(io.Discard, c)
		}(c)
	}
}
