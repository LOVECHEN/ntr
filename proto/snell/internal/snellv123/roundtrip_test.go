package snellv123

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// TestRoundtrip:v1/v2/v3 客户端 ↔ 服务端经真 TCP 往返(含命令握手 + 0x00 状态字节 + 双向数据 + 大包)。
func TestRoundtrip(t *testing.T) {
	cases := []struct {
		name       string
		chacha     bool
		connectCmd byte
	}{
		{"v1-chacha", true, CmdConnect},
		{"v2-aes-connectv2", false, CmdConnectReuse},
		{"v3-aes", false, CmdConnect},
	}
	psk := []byte("snellv123-test-psk")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				res, err := (&Server{PSK: psk, ChaCha: c.chacha}).Accept(conn)
				if err != nil {
					return
				}
				if res.Host != "example.com" || res.Port != 80 {
					return
				}
				_, _ = io.Copy(res.Conn, res.Conn) // echo
			}()

			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			rc, err := (&Client{PSK: psk, ChaCha: c.chacha, ConnectCmd: c.connectCmd}).DialTCPOver(conn, "example.com", 80, nil)
			if err != nil {
				t.Fatalf("DialTCPOver: %v", err)
			}

			// 首段小数据。
			if _, err := rc.Write([]byte("hello-snell")); err != nil {
				t.Fatalf("write1: %v", err)
			}
			got := make([]byte, len("hello-snell"))
			if _, err := io.ReadFull(rc, got); err != nil {
				t.Fatalf("read1: %v", err)
			}
			if string(got) != "hello-snell" {
				t.Fatalf("echo1 不符:%q", got)
			}

			// 大包(跨多 AEAD 块)。
			big := bytes.Repeat([]byte("Z"), 50000)
			if _, err := rc.Write(big); err != nil {
				t.Fatalf("write2: %v", err)
			}
			got2 := make([]byte, len(big))
			if _, err := io.ReadFull(rc, got2); err != nil {
				t.Fatalf("read2: %v", err)
			}
			if !bytes.Equal(got2, big) {
				t.Fatal("echo2(大包)不符")
			}
		})
	}
}
