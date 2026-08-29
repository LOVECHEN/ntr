package tlsmirror

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// startDecoy 起一个进程内 TLS1.3 诱骗后端:握手后读并丢弃、不主动关(供镜像保活)。返回其 addr。
func startDecoy(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "decoy.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"decoy.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // 同时支持 1.2(显式 nonce 载体)与 1.3
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(io.Discard, c) }(c)
		}
	}()
	return ln.Addr().String()
}

// TestTLSMirrorRoundTrip:自环端到端 —— tlsmirror 服务端镜像到诱骗后端,客户端隧道收发字节。
// 覆盖 default / padding / watermark / padding+watermark 四组可选层组合。
func TestTLSMirrorRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name      string
		padding   bool
		watermark bool
		explicit  bool
	}{
		{"default", false, false, false},
		{"padding", true, false, false},
		{"watermark", false, true, false},
		{"padding+watermark", true, true, false},
		{"tls12-explicit-nonce", false, false, true},
		{"tls12-explicit+padding+watermark", true, true, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) { roundTrip(t, tc.padding, tc.watermark, tc.explicit) })
	}
}

func roundTrip(t *testing.T, padding, watermark, explicit bool) {
	decoy := startDecoy(t)
	key := GeneratePrimaryKey()
	var suites []uint16
	if explicit {
		suites = RecommendedExplicitNonceCipherSuites
	}

	// tlsmirror 服务端:接受载体 TCP,拨诱骗后端,ServeConnReady 产隐蔽 Conn。
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srvLn.Close() })

	serverConns := make(chan *Conn, 1)
	go func() {
		carrier, err := srvLn.Accept()
		if err != nil {
			return
		}
		forward, err := net.Dial("tcp", decoy)
		if err != nil {
			_ = carrier.Close()
			return
		}
		hidden, err := ServeConnReady(context.Background(), carrier, forward, ServerConfig{PrimaryKey: key, Padding: padding, Watermark: watermark, ExplicitNonceCipherSuites: suites})
		if err != nil {
			return
		}
		serverConns <- hidden
	}()

	// tlsmirror 客户端:拨服务端,载体真 TLS1.3 握手(镜像到诱骗后端),产隐蔽 Conn。
	raw, err := net.Dial("tcp", srvLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConn, err := Dial(context.Background(), raw, ClientConfig{
		PrimaryKey:                key,
		ServerName:                "decoy.example.com",
		SkipCertVerify:            true,
		Padding:                   padding,
		Watermark:                 watermark,
		ExplicitNonceCipherSuites: suites,
		CarrierTLS12:              explicit,
	})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientConn.Close()

	// 客户端先写(激活隐蔽通道 → 服务端 ServeConnReady 返回)。
	msg := []byte("hello tlsmirror covert channel — 你好镜像隧道")
	go func() { _, _ = clientConn.Write(msg) }()

	var serverConn *Conn
	select {
	case serverConn = <-serverConns:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not activate within 10s")
	}
	defer serverConn.Close()

	// 服务端读到客户端首帧。
	_ = serverConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("server got %q, want %q", got, msg)
	}

	// 反向:服务端写,客户端读。
	reply := []byte("ack from server — 服务端回执")
	go func() { _, _ = serverConn.Write(reply) }()
	_ = clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	rback := make([]byte, len(reply))
	if _, err := io.ReadFull(clientConn, rback); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(rback, reply) {
		t.Fatalf("client got %q, want %q", rback, reply)
	}
}

// TestPrimaryKeyCodec 校验主密钥编解码约束(标准 base64 32B)。
func TestPrimaryKeyCodec(t *testing.T) {
	k := GeneratePrimaryKey()
	raw, err := DecodePrimaryKey(k)
	if err != nil || len(raw) != 32 {
		t.Fatalf("decode generated key: %v len=%d", err, len(raw))
	}
	if _, err := DecodePrimaryKey(""); err == nil {
		t.Fatal("empty key should error")
	}
	if _, err := DecodePrimaryKey("not-base64!!!"); err == nil {
		t.Fatal("bad base64 should error")
	}
	if _, err := DecodePrimaryKey("YWJj"); err == nil {
		t.Fatal("short key should error")
	}
}
