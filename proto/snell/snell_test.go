package snell

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv6"
)

var testPSK = []byte("snell-v6-test-psk-0123456789abcd")

// TestFramingRoundTrip 验证 vendored 的 v6 framing 在 NTR 构建下 Sender→Receiver 往返一致。
func TestFramingRoundTrip(t *testing.T) {
	snd := snellv6.NewSender(testPSK, false)
	rcv := snellv6.NewReceiver(testPSK)
	payload := []byte("hello snell v6 world — quick brown fox")

	enc, err := snd.EncodeChunk(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rcv.DecodeChunk(bytes.NewReader(enc))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch\n got=%q\nwant=%q", got, payload)
	}
}

// TestClientHandshakeCommandFraming:proxy.Client.ClientHandshake 在下层 stream 上跑
// CONNECT 握手,对端用 vendored Receiver 解出第一块 = stage-S0 CONNECT 命令。
func TestClientHandshakeCommandFraming(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	type res struct {
		chunk []byte
		err   error
	}
	got := make(chan res, 1)
	go func() {
		rcv := snellv6.NewReceiver(testPSK)
		chunk, err := rcv.DecodeChunk(s)
		got <- res{chunk, err}
	}()

	p := &Proxy{}
	if _, err := p.ClientHandshake(context.Background(), pipeStream{c}, testPSK, addr.FromFqdn("example.com", 443)); err != nil {
		t.Fatal(err)
	}

	r := <-got
	if r.err != nil {
		t.Fatal(r.err)
	}
	want := append([]byte{1, 1, 0, 11}, []byte("example.com")...)
	want = append(want, 0x01, 0xBB)
	if !bytes.Equal(r.chunk, want) {
		t.Fatalf("command chunk mismatch\n got=%x\nwant=%x", r.chunk, want)
	}
}

// pipeStream 把 net.Pipe 的 net.Conn 包成 link.Stream(补 Unwrap)。
type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

// testAuth:按 clientID 解析用户(多用户归属)。
type testAuth map[string]cred.Ref

func (a testAuth) Auth(scheme string, key []byte) (cred.Ref, bool) {
	if scheme != "snell" {
		return cred.Ref{}, false
	}
	r, ok := a[string(key)]
	return r, ok
}
