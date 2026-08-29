package mtproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestFakeTLSHandshakeRoundTrip:客户端 ClientHello → 服务端解析+校验 → ServerHello → 客户端校验。
func TestFakeTLSHandshakeRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef")
	host := "storage.googleapis.com"

	hello, clientRandom, err := buildClientHello(secret, host)
	if err != nil {
		t.Fatal(err)
	}
	// 结构:random 必须在偏移 11
	if len(hello) < tlsRandomOffset+tlsRandomLen {
		t.Fatal("ClientHello 太短")
	}
	if !bytes.Equal(hello[tlsRandomOffset:tlsRandomOffset+tlsRandomLen], clientRandom[:]) {
		t.Fatal("random 未落在偏移 11")
	}

	info, err := parseClientHello(bufio.NewReader(bytes.NewReader(hello)))
	if err != nil {
		t.Fatalf("服务端解析 ClientHello 失败:%v", err)
	}
	if info.random != clientRandom {
		t.Fatal("解析出的 random 与客户端不符")
	}
	if info.cipherSuite == 0 || info.cipherSuite&greaseMask == greaseValue {
		t.Fatalf("应取到非 GREASE cipher suite,得到 %#x", info.cipherSuite)
	}
	if err := verifyClientHello(info, secret, defaultTimeSkew); err != nil {
		t.Fatalf("digest 校验失败:%v", err)
	}

	// 服务端合成三段响应,客户端校验
	pkt, err := buildServerHello(info, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := readServerHello(bufio.NewReader(bytes.NewReader(pkt)), secret, clientRandom); err != nil {
		t.Fatalf("客户端校验 ServerHello 失败:%v", err)
	}
}

// TestFakeTLSWrongSecret:secret 不符时 ClientHello digest 校验必须失败。
func TestFakeTLSWrongSecret(t *testing.T) {
	hello, _, err := buildClientHello([]byte("0123456789abcdef"), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	info, err := parseClientHello(bufio.NewReader(bytes.NewReader(hello)))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyClientHello(info, []byte("WRONGWRONGWRONG!"), defaultTimeSkew); err == nil {
		t.Fatal("错误 secret 应导致 digest 校验失败")
	}
}

// TestFakeTLSTimeSkew:时间戳超出容差必须被拒(防重放)。
func TestFakeTLSTimeSkew(t *testing.T) {
	secret := []byte("0123456789abcdef")
	hello, _, err := buildClientHello(secret, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	info, err := parseClientHello(bufio.NewReader(bytes.NewReader(hello)))
	if err != nil {
		t.Fatal(err)
	}
	// 容差设成 0 之外的极小值,当前时间戳仍应在内;用负向极限模拟过期
	if err := verifyClientHello(info, secret, time.Nanosecond); err == nil {
		t.Fatal("纳秒级容差下应判定时间偏移超限")
	}
}

// TestTLSConnRecordRoundTrip:tlsConn 双向封/拆 ApplicationData 记录,并跳过非 AppData 记录。
func TestTLSConnRecordRoundTrip(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	c := newTLSConn(cli, nil)
	s := newTLSConn(srv, nil)

	msg := bytes.Repeat([]byte("payload-"), 100)
	go func() { _, _ = c.Write(msg) }()
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("记录往返不一致")
	}

	// 服务端先发一条 ChangeCipherSpec(应被读侧跳过),再发数据
	go func() {
		_, _ = srv.Write(changeCipherSpecRecord[:])
		_ = writeRecord(srv, []byte("after-ccs"))
	}()
	buf := make([]byte, len("after-ccs"))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "after-ccs" {
		t.Fatalf("应跳过 CCS 记录读到数据,得到 %q", buf)
	}
}

// TestWriteRecordChunking:超过单记录上限的载荷自动切块,且每块头部合法。
func TestWriteRecordChunking(t *testing.T) {
	var buf bytes.Buffer
	payload := bytes.Repeat([]byte{0xAB}, maxRecordPayload+1234)
	if err := writeRecord(&buf, payload); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	total, records := 0, 0
	for len(out) > 0 {
		if len(out) < recHeaderLen {
			t.Fatal("残缺记录头")
		}
		if out[0] != recTypeApplicationData || out[1] != 0x03 || out[2] != 0x03 {
			t.Fatalf("记录头非法:%x", out[:3])
		}
		n := int(binary.BigEndian.Uint16(out[3:5]))
		if n > maxRecordPayload {
			t.Fatalf("单记录载荷 %d 超上限 %d", n, maxRecordPayload)
		}
		total += n
		records++
		out = out[recHeaderLen+n:]
	}
	if total != len(payload) {
		t.Fatalf("切块后总长 %d != 原始 %d", total, len(payload))
	}
	if records != 2 {
		t.Fatalf("应切成 2 条记录,得到 %d", records)
	}
}
