package service

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestParseTLSSNI(t *testing.T) {
	cli, srv := net.Pipe()
	go func() {
		_ = tls.Client(cli, &tls.Config{ServerName: "sni.example.com", InsecureSkipVerify: true}).Handshake()
	}()
	buf := make([]byte, 4096)
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := srv.Read(buf)
	_ = srv.Close()
	host, ok := parseTLSSNI(buf[:n])
	if !ok || host != "sni.example.com" {
		t.Fatalf("parseTLSSNI=%q,%v 期望 sni.example.com", host, ok)
	}
}

func TestParseHTTPHost(t *testing.T) {
	for _, tc := range []struct {
		req  string
		want string
		ok   bool
	}{
		{"GET /x HTTP/1.1\r\nHost: web.example.com:80\r\nUA: t\r\n\r\n", "web.example.com", true},
		{"GET / HTTP/1.1\r\nHost: bare.test\r\n\r\n", "bare.test", true},
		{"NOTHTTP garbage", "", false},
		{"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n", "", false}, // IP 不算
	} {
		host, ok := parseHTTPHost([]byte(tc.req))
		if ok != tc.ok || host != tc.want {
			t.Errorf("parseHTTPHost(%q)=%q,%v 期望 %q,%v", tc.req, host, ok, tc.want, tc.ok)
		}
	}
}

func TestParseTLSSNINotTLS(t *testing.T) {
	if _, ok := parseTLSSNI([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Error("非 TLS 不该解出 SNI")
	}
}

func TestSniffReplayLossless(t *testing.T) {
	// sniff 后 replay 必须能读回完整首包(SNI 已被 peek 但字节不丢)
	cli, srv := net.Pipe()
	go func() {
		_ = tls.Client(cli, &tls.Config{ServerName: "rp.example.com", InsecureSkipVerify: true}).Handshake()
	}()
	proto, domain, replay, _ := sniff(connStream{srv}, 2*time.Second)
	if domain != "rp.example.com" || proto == 0 {
		t.Fatalf("sniff domain=%q proto=%d", domain, proto)
	}
	// replay 首字节应是 TLS record 头 0x16(首包没丢)
	b := make([]byte, 1)
	_ = replay.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := replay.Read(b)
	_ = replay.Close()
	if n != 1 || b[0] != 0x16 {
		t.Errorf("replay 首字节=%x n=%d 期望 0x16(首包未丢)", b, n)
	}
}
