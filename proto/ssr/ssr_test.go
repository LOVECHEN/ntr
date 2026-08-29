package ssr

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/internal/ssr/shadowstream"
	sscore "github.com/LOVECHEN/ntr/internal/ssr/sscore"
)

type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

var _ link.Stream = connStream{}

// TestSSRClientCipherRoundTrip:combo=aes-256-cfb/origin/plain 时 obfs 与 protocol 均为透传,
// 线上 = [IV][流加密(SOCKS5目标头 + 载荷)]。本测在管道另一端按 SS 流加密逆解,验客户端产出的
// 目标头 + 载荷可被标准 SS 服务端逐字节还原(即线格式正确)。
func TestSSRClientCipherRoundTrip(t *testing.T) {
	const pw = "test-password-42"
	built, err := Build(context.Background(), Config{Cipher: "aes-256-cfb", Password: pw, Protocol: "origin", Obfs: "plain"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := built.(*Proxy)

	cliConn, srvConn := net.Pipe()
	dst := addr.FromFqdn("example.com", 443)
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	errCh := make(chan error, 1)
	go func() {
		s, err := p.ClientHandshake(context.Background(), connStream{cliConn}, nil, dst)
		if err != nil {
			errCh <- err
			return
		}
		_, err = s.Write(payload)
		errCh <- err
	}()

	// 服务端逆解:读 16B IV,再用 aes-256-cfb Decrypter 还原全部明文。
	ciph, err := sscore.PickCipher("aes-256-cfb", nil, pw)
	if err != nil {
		t.Fatal(err)
	}
	sc := ciph.(*sscore.StreamCipher)
	_ = srvConn.SetDeadline(time.Now().Add(5 * time.Second))

	iv := make([]byte, sc.IVSize())
	if _, err := io.ReadFull(srvConn, iv); err != nil {
		t.Fatalf("读 IV:%v", err)
	}
	want := append(serializeSSRAddr(dst), payload...)
	dec := sc.Decrypter(iv)
	ct := make([]byte, len(want))
	if _, err := io.ReadFull(srvConn, ct); err != nil {
		t.Fatalf("读密文:%v", err)
	}
	pt := make([]byte, len(ct))
	dec.XORKeyStream(pt, ct)

	if err := <-errCh; err != nil {
		t.Fatalf("客户端握手/写:%v", err)
	}
	if string(pt) != string(want) {
		t.Fatalf("解出明文不符:\n got %x\nwant %x", pt, want)
	}
	// 前几字节应是 SOCKS5 域名头 03 0b "example.com" 04bb。
	if pt[0] != 0x03 || pt[1] != byte(len("example.com")) {
		t.Fatalf("目标头 ATYP/len 不符:%x", pt[:2])
	}
	_ = shadowstream.Conn{} // 触及 vendored 类型(链接校验)
}

// TestSSRServerRoundTrip:NTR ssr 客户端 → NTR ssr 服务端经真 TCP,验服务端栈逆向(对称 cipher 解密 +
// 服务端 protocol Decode/Encode + 读 SOCKS5 目标)+ 多段双向数据往返自洽。覆盖服务端已支持的插件组合。
func TestSSRServerRoundTrip(t *testing.T) {
	combos := []Config{
		{Cipher: "aes-256-cfb", Password: "pw-a", Protocol: "origin", Obfs: "plain"},
		{Cipher: "aes-256-cfb", Password: "pw-b", Protocol: "auth_aes128_sha1", Obfs: "plain"},
		{Cipher: "rc4-md5", Password: "pw-c", Protocol: "auth_aes128_md5", Obfs: "plain"},
		{Cipher: "chacha20-ietf", Password: "pw-d", Protocol: "auth_aes128_sha1", Obfs: "plain"},
		{Cipher: "aes-256-cfb", Password: "pw-e", Protocol: "origin", Obfs: "http_simple"},
		{Cipher: "aes-256-cfb", Password: "pw-f", Protocol: "auth_aes128_sha1", Obfs: "http_simple"},
		{Cipher: "aes-256-cfb", Password: "pw-g", Protocol: "auth_aes128_md5", Obfs: "http_post"},
		{Cipher: "aes-256-cfb", Password: "pw-h", Protocol: "auth_aes128_sha1", Obfs: "random_head"},
		{Cipher: "aes-256-cfb", Password: "pw-i", Protocol: "auth_sha1_v4", Obfs: "plain"},
		{Cipher: "rc4-md5", Password: "pw-j", Protocol: "auth_sha1_v4", Obfs: "http_simple"},
		{Cipher: "aes-256-cfb", Password: "pw-k", Protocol: "auth_chain_a", Obfs: "plain"},
		{Cipher: "rc4-md5", Password: "pw-l", Protocol: "auth_chain_a", Obfs: "http_simple"},
		{Cipher: "aes-256-cfb", Password: "pw-m", Protocol: "auth_chain_b", Obfs: "plain"},
		{Cipher: "rc4-md5", Password: "pw-n", Protocol: "auth_chain_b", Obfs: "random_head"},
		{Cipher: "aes-256-cfb", Password: "pw-o", Protocol: "origin", Obfs: "tls1.2_ticket_auth"},
		{Cipher: "aes-256-cfb", Password: "pw-p", Protocol: "auth_aes128_sha1", Obfs: "tls1.2_ticket_auth"},
		{Cipher: "rc4-md5", Password: "pw-q", Protocol: "auth_chain_a", Obfs: "tls1.2_ticket_auth"},
	}
	for _, cfg := range combos {
		name := cfg.Cipher + "/" + cfg.Protocol + "/" + cfg.Obfs
		t.Run(name, func(t *testing.T) {
			cliBuilt, err := Build(context.Background(), cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			srvBuilt, err := Build(context.Background(), cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			cli := cliBuilt.(*Proxy)
			srv := srvBuilt.(*Proxy)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			dst := addr.FromFqdn("target.example", 8080)
			gotDst := make(chan addr.Socksaddr, 1)
			srvErr := make(chan error, 1)

			go func() {
				c, err := ln.Accept()
				if err != nil {
					srvErr <- err
					return
				}
				s, req, err := srv.ServerHandshake(context.Background(), connStream{c}, nil)
				if err != nil {
					srvErr <- err
					return
				}
				gotDst <- req.Dst
				// echo 两段(首段裹在 auth 头 / 首 chunk,第二段是后续 chunk)。
				buf := make([]byte, 512)
				for i := 0; i < 2; i++ {
					n, e := s.Read(buf)
					if e != nil {
						srvErr <- e
						return
					}
					if _, e := s.Write(buf[:n]); e != nil {
						srvErr <- e
						return
					}
				}
				srvErr <- nil
			}()

			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			cs, err := cli.ClientHandshake(context.Background(), connStream{c}, nil, dst)
			if err != nil {
				t.Fatalf("ClientHandshake:%v", err)
			}
			defer cs.Close()
			_ = cs.SetDeadline(time.Now().Add(5 * time.Second))

			for _, msg := range [][]byte{[]byte("ssr-srv-seg1-first"), []byte("ssr-srv-seg2-second")} {
				want := string(msg) // 存副本:auth_chain 的 packData 会就地 RC4 改写输入缓冲
				if _, err := cs.Write(msg); err != nil {
					t.Fatalf("write:%v", err)
				}
				got := make([]byte, len(want))
				if _, err := io.ReadFull(cs, got); err != nil {
					t.Fatalf("read echo:%v", err)
				}
				if string(got) != want {
					t.Fatalf("echo 不符:got %q want %q", got, want)
				}
			}
			if err := <-srvErr; err != nil {
				t.Fatalf("服务端:%v", err)
			}
			rd := <-gotDst
			if rd.Fqdn != dst.Fqdn || rd.Port != dst.Port {
				t.Fatalf("服务端解出目标不符:got %v want %v", rd, dst)
			}
		})
	}
}

// TestSSRClientCombos:多组 cipher/protocol/obfs 各跑一次握手 + 一段写,断言不 panic、不报错、有字节上行。
// 服务端仅排空(不校验语义,语义正确性交给 Docker 对参考 SSR 服务端的交叉验证)。
func TestSSRClientCombos(t *testing.T) {
	combos := []Config{
		{Cipher: "rc4-md5", Password: "pw1", Protocol: "auth_sha1_v4", Obfs: "http_simple"},
		{Cipher: "aes-128-cfb", Password: "pw2", Protocol: "auth_aes128_md5", Obfs: "tls1.2_ticket_auth"},
		{Cipher: "aes-256-ctr", Password: "pw3", Protocol: "auth_aes128_sha1", Obfs: "http_post"},
		{Cipher: "chacha20-ietf", Password: "pw4", Protocol: "auth_chain_a", Obfs: "plain"},
		{Cipher: "chacha20-ietf", Password: "pw5", Protocol: "auth_chain_b", Obfs: "random_head"},
		{Cipher: "none", Password: "pw6", Protocol: "origin", Obfs: "plain"},
	}
	dst := addr.FromFqdn("cross.example", 80)
	for _, cfg := range combos {
		name := cfg.Cipher + "/" + cfg.Protocol + "/" + cfg.Obfs
		t.Run(name, func(t *testing.T) {
			built, err := Build(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Build:%v", err)
			}
			p := built.(*Proxy)

			// TCP 环回(有缓冲,不像 net.Pipe 每 Write 阻塞);服务端后台 io.Copy 排空累计字节数。
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			gotBytes := make(chan int64, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					gotBytes <- 0
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				n, _ := io.Copy(io.Discard, c)
				gotBytes <- n
			}()

			cliConn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}

			done := make(chan error, 1)
			go func() {
				s, err := p.ClientHandshake(context.Background(), connStream{cliConn}, nil, dst)
				if err != nil {
					done <- err
					return
				}
				_, err = s.Write([]byte("hello-ssr"))
				_ = cliConn.Close() // 关闭以让服务端 io.Copy 返回
				done <- err
			}()

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("握手/写:%v", err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("握手超时")
			}
			if n := <-gotBytes; n <= 0 {
				t.Fatal("服务端未收到任何上行字节")
			}
		})
	}
}
