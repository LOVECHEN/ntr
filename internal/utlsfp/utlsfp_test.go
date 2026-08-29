package utlsfp

import (
	"bytes"
	"context"
	cryptotls "crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// captureClientHello 起一个只读首个 TLS 记录的假服务端,返回客户端发出的 ClientHello 原始字节。
// dial 回调负责用待测方式发起握手(握手必然失败,因为服务端不回应 —— 我们只要 ClientHello)。
func captureClientHello(t *testing.T, dial func(conn net.Conn)) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		var hdr [5]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			got <- nil
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[3:5]))
		body := make([]byte, n)
		if _, err := io.ReadFull(c, body); err != nil {
			got <- nil
			return
		}
		got <- append(hdr[:], body...)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer conn.Close()
		dial(conn)
	}()

	select {
	case b := <-got:
		if b == nil {
			t.Fatal("未捕获到 ClientHello")
		}
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("捕获 ClientHello 超时")
		return nil
	}
}

// cipherSuitesOf 从 ClientHello 记录里取 cipher_suites 列表。
func cipherSuitesOf(t *testing.T, hello []byte) []uint16 {
	t.Helper()
	// 5 记录头 + 1 类型 + 3 长度 + 2 版本 + 32 random = 43,随后 session_id
	p := 43
	if p >= len(hello) {
		t.Fatal("ClientHello 过短")
	}
	p += 1 + int(hello[p]) // session_id
	if p+2 > len(hello) {
		t.Fatal("ClientHello 截断")
	}
	n := int(binary.BigEndian.Uint16(hello[p : p+2]))
	p += 2
	var out []uint16
	for i := 0; i+1 < n && p+i+1 < len(hello); i += 2 {
		out = append(out, binary.BigEndian.Uint16(hello[p+i:p+i+2]))
	}
	return out
}

// hasGREASE 判断 cipher suites 里是否含 GREASE 值(0x?a?a 且高低字节相同)——
// 真实 Chrome 必发 GREASE,Go 标准库 crypto/tls 不发。这是最直观的指纹差异。
func hasGREASE(suites []uint16) bool {
	for _, s := range suites {
		if s&0x0f0f == 0x0a0a && byte(s>>8) == byte(s) {
			return true
		}
	}
	return false
}

// TestFingerprintChangesClientHello:uTLS 指纹必须真正改变 ClientHello 字节,
// 且与 Go 标准库 crypto/tls 明显不同(GREASE / cipher suites 列表)。
func TestFingerprintChangesClientHello(t *testing.T) {
	cfg := &cryptotls.Config{ServerName: "example.com", InsecureSkipVerify: true, NextProtos: []string{"h2"}}

	// 基线:标准 crypto/tls(fingerprint 为空)
	stdHello := captureClientHello(t, func(c net.Conn) {
		_, _ = Dial(context.Background(), c, cfg, "")
	})
	stdSuites := cipherSuitesOf(t, stdHello)
	if hasGREASE(stdSuites) {
		t.Log("注意:Go 标准库本次带了 GREASE(版本行为变化),后续断言以字节差异为准")
	}

	// uTLS Chrome
	chromeHello := captureClientHello(t, func(c net.Conn) {
		_, _ = Dial(context.Background(), c, cfg, "chrome")
	})
	chromeSuites := cipherSuitesOf(t, chromeHello)

	if bytes.Equal(stdHello, chromeHello) {
		t.Fatal("uTLS chrome 指纹与标准 crypto/tls 的 ClientHello 完全相同 —— 指纹伪装未生效")
	}
	if !hasGREASE(chromeSuites) {
		t.Errorf("Chrome 指纹的 cipher suites 应含 GREASE,得到 %#x", chromeSuites)
	}
	t.Logf("标准 crypto/tls:%d 字节,%d 个 cipher suites", len(stdHello), len(stdSuites))
	t.Logf("uTLS chrome   :%d 字节,%d 个 cipher suites(含 GREASE=%v)", len(chromeHello), len(chromeSuites), hasGREASE(chromeSuites))

	// 不同浏览器指纹之间也应彼此不同
	firefoxHello := captureClientHello(t, func(c net.Conn) {
		_, _ = Dial(context.Background(), c, cfg, "firefox")
	})
	if bytes.Equal(chromeHello, firefoxHello) {
		t.Error("chrome 与 firefox 指纹的 ClientHello 不应相同")
	}
}

// TestParseFingerprint:指纹名映射与"空=不启用"语义。
func TestParseFingerprint(t *testing.T) {
	if _, ok := Parse(""); ok {
		t.Error("空指纹名应返回 ok=false(走标准 crypto/tls)")
	}
	for _, name := range []string{"chrome", "chrome_120", "firefox", "safari", "ios", "edge", "random"} {
		if _, ok := Parse(name); !ok {
			t.Errorf("%s 应被识别", name)
		}
	}
	// 未知名字回落 Chrome 而非静默禁用(避免"配了指纹却没生效")
	id, ok := Parse("no-such-browser")
	if !ok {
		t.Fatal("未知指纹名应回落到 Chrome 而非禁用")
	}
	chrome, _ := Parse("chrome")
	if id.Client != chrome.Client {
		t.Errorf("未知指纹名应回落 Chrome,得到 %s", id.Client)
	}
}

// TestALPNPreserved:NextProtos(h2)必须透传到 uTLS,否则 naive/trusttunnel 协商不到 h2。
func TestALPNPreserved(t *testing.T) {
	cfg := &cryptotls.Config{ServerName: "example.com", InsecureSkipVerify: true, NextProtos: []string{"h2"}}
	hello := captureClientHello(t, func(c net.Conn) {
		_, _ = Dial(context.Background(), c, cfg, "chrome")
	})
	// ALPN 扩展体里应出现 "h2"
	if !bytes.Contains(hello, []byte{0x02, 'h', '2'}) {
		t.Error("uTLS ClientHello 应携带 ALPN h2")
	}
}
