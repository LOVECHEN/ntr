package vlessenc

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
)

type connStreamT struct{ net.Conn }

func (connStreamT) Unwrap() any { return nil }

var _ link.Stream = connStreamT{}

// TestVlessEncSelfLoop:X25519 密钥对,NTR 客户端 ClientWrap(公钥)↔ 服务端 ServerWrap(私钥)经真 TCP,
// 验 VLESS Encryption(ML-KEM-768 pfs + X25519 nfs)握手 + AEAD 分帧数据双向往返。覆盖 native/xorpub/random。
func TestVlessEncSelfLoop(t *testing.T) {
	for _, mode := range []string{"native", "xorpub", "random"} {
		t.Run(mode, func(t *testing.T) {
			priv, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			privB64 := base64.RawURLEncoding.EncodeToString(priv.Bytes())
			pubB64 := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())

			cliBuilt, err := Build(context.Background(), Config{Keys: []string{pubB64}, Mode: mode}, nil)
			if err != nil {
				t.Fatal(err)
			}
			srvBuilt, err := Build(context.Background(), Config{Keys: []string{privB64}, Mode: mode}, nil)
			if err != nil {
				t.Fatal(err)
			}
			cli := cliBuilt.(*Transport)
			srv := srvBuilt.(*Transport)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			msg := []byte("vlessenc-postquantum-hello-42-" + mode)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				s, err := srv.ServerWrap(context.Background(), connStreamT{c})
				if err != nil {
					return
				}
				defer s.Close()
				buf := make([]byte, 256)
				n, e := s.Read(buf)
				if e != nil {
					return
				}
				_, _ = s.Write(buf[:n]) // echo
				time.Sleep(200 * time.Millisecond)
			}()

			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			cs, err := cli.ClientWrap(context.Background(), connStreamT{c})
			if err != nil {
				t.Fatalf("ClientWrap:%v", err)
			}
			defer cs.Close()
			_ = cs.SetDeadline(time.Now().Add(5 * time.Second))

			if _, err := cs.Write(msg); err != nil {
				t.Fatalf("write:%v", err)
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(cs, got); err != nil {
				t.Fatalf("read echo:%v", err)
			}
			if string(got) != string(msg) {
				t.Fatalf("echo 不符:got %q want %q", got, msg)
			}
		})
	}
}
