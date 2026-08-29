package mtproto

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// TestObfuscatedHandshakeRoundTrip:客户端握手 → 服务端解析,DC 索引与双向 CTR 数据往返一致。
func TestObfuscatedHandshakeRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef") // 16 字节
	for _, dc := range []int{1, 2, 5, -3} {
		cli, srv := net.Pipe()
		type res struct {
			c  *obfsConn
			dc int
			e  error
		}
		done := make(chan res, 1)
		go func() {
			c, gotDC, err := readObfuscatedHandshake(srv, secret)
			done <- res{c, gotDC, err}
		}()
		cc, err := sendObfuscatedHandshake(cli, secret, dc)
		if err != nil {
			t.Fatalf("dc=%d 客户端握手失败:%v", dc, err)
		}
		r := <-done
		if r.e != nil {
			t.Fatalf("dc=%d 服务端握手失败:%v", dc, r.e)
		}
		wantDC := dc
		if wantDC < 0 {
			wantDC = -wantDC // 负数取绝对值
		}
		if r.dc != wantDC {
			t.Fatalf("DC 不符:得到 %d,want %d", r.dc, wantDC)
		}

		// 客户端 → 服务端
		msg := []byte("client-to-server-payload")
		go func() { _, _ = cc.Write(msg) }()
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(r.c, got); err != nil {
			t.Fatalf("服务端读失败:%v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("上行不一致:%q != %q", got, msg)
		}
		// 服务端 → 客户端
		msg2 := []byte("server-to-client-payload")
		go func() { _, _ = r.c.Write(msg2) }()
		got2 := make([]byte, len(msg2))
		if _, err := io.ReadFull(cc, got2); err != nil {
			t.Fatalf("客户端读失败:%v", err)
		}
		if !bytes.Equal(got2, msg2) {
			t.Fatalf("下行不一致:%q != %q", got2, msg2)
		}
		cli.Close()
		srv.Close()
	}
}

// TestObfuscatedWrongSecret:secret 不符时解密出的 connType 对不上,握手必须被拒。
func TestObfuscatedWrongSecret(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	errc := make(chan error, 1)
	go func() {
		_, _, err := readObfuscatedHandshake(srv, []byte("WRONGWRONGWRONG!"))
		errc <- err
	}()
	go func() { _, _ = sendObfuscatedHandshake(cli, []byte("0123456789abcdef"), 2) }()
	if err := <-errc; err == nil {
		t.Fatal("期望错误 secret 被拒,但握手成功了")
	}
}

// TestBadPrefixRejected:反探测前缀(HTTP 方法 / TLS 记录 / 0xef / [4:8) 全零)必须被识别。
func TestBadPrefixRejected(t *testing.T) {
	mk := func(prefix []byte) []byte {
		d := make([]byte, hfLen)
		for i := range d {
			d[i] = byte(i + 1) // 保证 [4:8) 非零
		}
		copy(d, prefix)
		return d
	}
	bad := map[string][]byte{
		"0xef 首字节": {0xef},
		"HEAD":     []byte("HEAD"),
		"POST":     []byte("POST"),
		"GET ":     []byte("GET "),
		"OPTI":     []byte("OPTI"),
		"TLS 记录":   {0x16, 0x03, 0x01, 0x02},
		"dddddddd": {0xdd, 0xdd, 0xdd, 0xdd},
		"eeeeeeee": {0xee, 0xee, 0xee, 0xee},
	}
	for name, p := range bad {
		if !badPrefix(mk(p)) {
			t.Errorf("%s 应被判为禁止前缀", name)
		}
	}
	// [4:8) 全零也禁止
	z := mk(nil)
	z[4], z[5], z[6], z[7] = 0, 0, 0, 0
	if !badPrefix(z) {
		t.Error("[4:8) 全零应被判为禁止前缀")
	}
	// 正常随机帧不应命中
	h, err := generateHandshake(2)
	if err != nil {
		t.Fatal(err)
	}
	if badPrefix(h.data[:]) {
		t.Error("生成的合法帧不应命中禁止前缀")
	}
}

// TestHandshakeFrameLayout:字段偏移与 DC 编码符合线格式。
func TestHandshakeFrameLayout(t *testing.T) {
	h, err := generateHandshake(4)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.data) != 64 {
		t.Fatalf("帧长应为 64,得到 %d", len(h.data))
	}
	if len(h.key()) != 32 || len(h.iv()) != 16 || len(h.connType()) != 4 {
		t.Fatalf("字段长度错:key=%d iv=%d connType=%d", len(h.key()), len(h.iv()), len(h.connType()))
	}
	if !bytes.Equal(h.connType(), hfConnectionType[:]) {
		t.Fatalf("connType 应为 dddddddd,得到 %x", h.connType())
	}
	if got := binary.LittleEndian.Uint16(h.data[60:62]); got != 4 {
		t.Fatalf("DC 应小端编码为 4,得到 %d", got)
	}
	if h.dc() != 4 {
		t.Fatalf("dc() 应返回 4,得到 %d", h.dc())
	}
	// revert 只逆序 [8:56),其余不动
	orig := *h
	h.revert()
	if !bytes.Equal(h.data[:8], orig.data[:8]) || !bytes.Equal(h.data[56:], orig.data[56:]) {
		t.Fatal("revert 不应改动 [0:8) 与 [56:64)")
	}
	rev := make([]byte, 48)
	copy(rev, orig.data[8:56])
	for i, j := 0, 47; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	if !bytes.Equal(h.data[8:56], rev) {
		t.Fatal("revert 应逆序 [8:56)")
	}
}

// TestDCZeroFallback:DC 索引 0 回落到默认 DC。
func TestDCZeroFallback(t *testing.T) {
	h := &handshakeFrame{}
	binary.LittleEndian.PutUint16(h.data[60:62], 0)
	if h.dc() != defaultDC {
		t.Fatalf("DC 0 应回落到 %d,得到 %d", defaultDC, h.dc())
	}
}
