package kcptun

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestKcptunRoundTrip:进程内自环 —— kcptun 服务端(UDP)accept smux 流并回显,客户端开流收发字节。
// 覆盖 comp 开/关、aes 与 none 两种 crypt。
func TestKcptunRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		crypt  string
		nocomp bool
	}{
		{"aes+comp", "aes", false},
		{"aes+nocomp", "aes", true},
		{"none+comp", "none", false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Key: "testkey", Crypt: tc.crypt, Mode: "fast", NoComp: tc.nocomp}

			// 服务端:UDP loopback + kcptun serve,handler 回显。
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srvAddr := pc.LocalAddr().String()
			srv := newServer(cfg)
			go func() { _ = srv.serve(pc, func(c net.Conn) { _, _ = io.Copy(c, c) }) }()
			t.Cleanup(func() { _ = pc.Close() })

			// 客户端:开一条流,收发。
			cli := newClient(cfg)
			raddr, err := net.ResolveUDPAddr("udp", srvAddr)
			if err != nil {
				t.Fatal(err)
			}
			dial := func(_ context.Context) (net.PacketConn, net.Addr, error) {
				lp, err := net.ListenUDP("udp", nil)
				return lp, raddr, err
			}
			st, err := cli.openStream(context.Background(), dial)
			if err != nil {
				t.Fatalf("open stream: %v", err)
			}
			defer st.Close()

			msg := []byte("hello kcptun over KCP+FEC+smux — 你好 KCP 隧道")
			_ = st.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := st.Write(msg); err != nil {
				t.Fatalf("write: %v", err)
			}
			_ = st.SetReadDeadline(time.Now().Add(10 * time.Second))
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(st, got); err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("got %q want %q", got, msg)
			}
		})
	}
}

// TestKcptunDefaults 校验默认值与 mode 映射同 mihomo/xtaci-kcptun。
func TestKcptunDefaults(t *testing.T) {
	c := Config{}
	c.FillDefaults()
	if c.Key != "it's a secrect" || c.Crypt != "aes" || c.Mode != "fast" {
		t.Fatalf("默认 key/crypt/mode 不对: %q %q %q", c.Key, c.Crypt, c.Mode)
	}
	if c.MTU != 1350 || c.DataShard != 10 || c.ParityShard != 3 || c.SmuxVer != 1 {
		t.Fatalf("默认 mtu/shard/smuxver 不对: %d %d %d %d", c.MTU, c.DataShard, c.ParityShard, c.SmuxVer)
	}
	// fast 模式:nodelay=0 interval=30 resend=2 nc=1
	if c.NoDelay != 0 || c.Interval != 30 || c.Resend != 2 || c.NoCongestion != 1 {
		t.Fatalf("fast 模式 KCP 参数不对: %d %d %d %d", c.NoDelay, c.Interval, c.Resend, c.NoCongestion)
	}
	if c.NewBlock() == nil {
		t.Fatal("aes 默认应有 block")
	}
	// none crypt 也应产出非 nil block(NewNoneBlockCrypt)
	cn := Config{Crypt: "null"}
	cn.FillDefaults()
	cn.Crypt = "null"
	if cn.NewBlock() != nil {
		t.Fatal("null crypt 应为 nil block")
	}
}
