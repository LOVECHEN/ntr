package mtproto

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
)

// mkSecret 造一个合法 ee secret 的 hex 文本:0xEE ‖ key[16] ‖ host。
func mkSecret(host string) string { return mkSecretKey("0123456789abcdef", host) }

// mkSecretKey 用指定 16 字节 key 造 ee secret。
func mkSecretKey(key, host string) string {
	raw := append([]byte{secretFakeTLSFirstByte}, []byte(key)...)
	return hex.EncodeToString(append(raw, host...))
}

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

func newProxy(t *testing.T, cfg Config) *Proxy {
	t.Helper()
	v, err := Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return v.(*Proxy)
}

// TestParseSecret:ee secret 的解析与各类非法输入的拒绝。
func TestParseSecret(t *testing.T) {
	key, host, err := parseSecret(mkSecret("storage.googleapis.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != obfsSecretKeyLen {
		t.Fatalf("key 应为 16 字节,得到 %d", len(key))
	}
	if host != "storage.googleapis.com" {
		t.Fatalf("host 解析错:%q", host)
	}
	// 官方样例(mtg secret.go 注释):ee + key16 + "storage.googleapis.com"
	k2, h2, err := parseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	if err != nil {
		t.Fatalf("官方样例应可解析:%v", err)
	}
	if h2 != "storage.googleapis.com" {
		t.Fatalf("官方样例 host 应为 storage.googleapis.com,得到 %q", h2)
	}
	if hex.EncodeToString(k2) != "367a189aee18fa31c190054efd4a8e95" {
		t.Fatalf("官方样例 key 不符:%x", k2)
	}

	for name, bad := range map[string]string{
		"空":         "",
		"非 hex/b64": "!!!!",
		"首字节非 ee":   hex.EncodeToString(append([]byte{0xdd}, bytes.Repeat([]byte{1}, 20)...)),
		"缺 host":    hex.EncodeToString(append([]byte{0xee}, bytes.Repeat([]byte{1}, 16)...)),
		"key 不足":    hex.EncodeToString([]byte{0xee, 0x01, 0x02}),
	} {
		if _, _, err := parseSecret(bad); err == nil {
			t.Errorf("%s 应被拒绝", name)
		}
	}
}

// TestMTProtoRoundTrip:客户端 ↔ 服务端完整握手(faketls + obfuscated2)+ 双向数据往返,
// 并验证服务端按 DC 索引合成目标地址。
func TestMTProtoRoundTrip(t *testing.T) {
	const host = "storage.googleapis.com"
	secret := mkSecret(host)

	for _, dc := range []int{1, 2, 4} {
		cli, srv := net.Pipe()
		cp := newProxy(t, Config{Secret: secret, DC: dc})
		sp := newProxy(t, Config{Secret: secret})

		type sres struct {
			s   io.ReadWriter
			req *proxyRequest
			e   error
		}
		done := make(chan sres, 1)
		go func() {
			st, req, err := sp.ServerHandshake(context.Background(), pipeStream{srv}, nil)
			if err != nil {
				done <- sres{e: err}
				return
			}
			done <- sres{s: st, req: &proxyRequest{Dst: req.Dst, Network: req.Network}}
		}()

		cs, err := cp.ClientHandshake(context.Background(), pipeStream{cli}, nil, addr.Socksaddr{})
		if err != nil {
			t.Fatalf("dc=%d 客户端握手失败:%v", dc, err)
		}
		r := <-done
		if r.e != nil {
			t.Fatalf("dc=%d 服务端握手失败:%v", dc, r.e)
		}
		if r.req.Network != endpoint.NetworkTCP {
			t.Fatalf("Network 应为 TCP")
		}
		// 服务端应把 Dst 合成为该 DC 的公开地址
		want := telegramCoreAddresses[dc]
		if r.req.Dst.String() != want {
			t.Fatalf("dc=%d Dst 应为 %s,得到 %s", dc, want, r.req.Dst)
		}

		// 双向数据
		up := []byte("client->server over mtproto")
		go func() { _, _ = cs.Write(up) }()
		got := make([]byte, len(up))
		if _, err := io.ReadFull(r.s, got); err != nil {
			t.Fatalf("服务端读失败:%v", err)
		}
		if !bytes.Equal(got, up) {
			t.Fatalf("上行不一致:%q != %q", got, up)
		}
		down := []byte("server->client over mtproto")
		go func() { _, _ = r.s.Write(down) }()
		got2 := make([]byte, len(down))
		if _, err := io.ReadFull(cs, got2); err != nil {
			t.Fatalf("客户端读失败:%v", err)
		}
		if !bytes.Equal(got2, down) {
			t.Fatalf("下行不一致:%q != %q", got2, down)
		}
		cli.Close()
		srv.Close()
	}
}

// TestMTProtoWrongSecret:secret 不符时服务端必须在 faketls digest 阶段就拒绝。
func TestMTProtoWrongSecret(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	cp := newProxy(t, Config{Secret: mkSecretKey("0123456789abcdef", "a.com")})
	sp := newProxy(t, Config{Secret: mkSecretKey("FEDCBA9876543210", "a.com")}) // key 不同

	errc := make(chan error, 1)
	go func() {
		_, _, err := sp.ServerHandshake(context.Background(), pipeStream{srv}, nil)
		errc <- err
	}()
	go func() { _, _ = cp.ClientHandshake(context.Background(), pipeStream{cli}, nil, addr.Socksaddr{}) }()
	if err := <-errc; err == nil {
		t.Fatal("secret 不符应被拒绝")
	}
}

// TestMTProtoSNIMismatch:key 相同但 host 不同时,服务端应在 SNI 校验处拒绝。
func TestMTProtoSNIMismatch(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	cp := newProxy(t, Config{Secret: mkSecretKey("0123456789abcdef", "a.com")})
	sp := newProxy(t, Config{Secret: mkSecretKey("0123456789abcdef", "b.com")})

	errc := make(chan error, 1)
	go func() {
		_, _, err := sp.ServerHandshake(context.Background(), pipeStream{srv}, nil)
		errc <- err
	}()
	go func() { _, _ = cp.ClientHandshake(context.Background(), pipeStream{cli}, nil, addr.Socksaddr{}) }()
	if err := <-errc; err == nil {
		t.Fatal("SNI 不符应被拒绝")
	}
}

// TestDCMapOverride:dc-map 覆盖内置表。
func TestDCMapOverride(t *testing.T) {
	p := newProxy(t, Config{Secret: mkSecret("a.com"), DCMap: map[int]string{2: "127.0.0.1:9999"}})
	got, err := p.dcAddr(2)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "127.0.0.1:9999" {
		t.Fatalf("dc-map 覆盖失效:%s", got)
	}
	// 未覆盖的 DC 仍走内置表
	got3, err := p.dcAddr(3)
	if err != nil {
		t.Fatal(err)
	}
	if got3.String() != telegramCoreAddresses[3] {
		t.Fatalf("未覆盖的 DC 应用内置表,得到 %s", got3)
	}
}

// proxyRequest 是测试内的轻量副本(避免直接依赖 proxy.Request 的其它字段)。
type proxyRequest struct {
	Dst     addr.Socksaddr
	Network endpoint.Network
}
