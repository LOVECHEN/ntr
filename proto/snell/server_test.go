package snell

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv6"
)

// TestServerHandshakeE2E:vendored Snell v6 客户端(我们的测试客户端)经统一 proxy.Server
// 接口连上 NTR snell 服务端,验证 ①解出正确 dst ②双向 relay 通 ③空 clientID → Ambient。
func TestServerHandshakeE2E(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()

	errc := make(chan error, 1)
	go func() { // 客户端(vendored engine)
		cli := &snellv6.Client{PSK: testPSK}
		rc, err := cli.DialTCPOver(c, "example.com", 443, nil)
		if err != nil {
			errc <- err
			return
		}
		if _, err := rc.Write([]byte("hello from client")); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, len("ack from server"))
		if _, err := io.ReadFull(rc, buf); err != nil {
			errc <- err
			return
		}
		if string(buf) != "ack from server" {
			errc <- fmt.Errorf("client got %q", buf)
			return
		}
		errc <- nil
	}()

	p := &Proxy{cfg: Config{PSK: testPSK}}
	stream, req, err := p.ServerHandshake(ctx, pipeStream{s}, testAuth{})
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst.String() != "example.com:443" {
		t.Fatalf("server decoded dst = %s, want example.com:443", req.Dst.String())
	}
	if req.Cred.ID != cred.Ambient {
		t.Fatalf("empty clientID should map to Ambient, got %d", req.Cred.ID)
	}

	pl := make([]byte, len("hello from client"))
	if _, err := io.ReadFull(stream, pl); err != nil {
		t.Fatal(err)
	}
	if string(pl) != "hello from client" {
		t.Fatalf("server read payload %q", pl)
	}
	if _, err := stream.Write([]byte("ack from server")); err != nil {
		t.Fatal(err)
	}

	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// TestServerHandshakeV6Piggyback:v6 客户端把 CONNECT 与目标首段数据合并进同一 AEAD chunk
// (initial 非 nil,省一个 RTT——标准做法)。服务端 relay 首次 Read 必须【先吐出这段 piggyback
// 数据】(修复:不丢弃 res.Initial),否则 target 首批字节缺失(HTTP 请求行/TLS ClientHello 残缺)。
// 跨实现(官方/mihomo v6 客户端 piggyback)才触发;NTR↔NTR 传 nil 不触发,故 happy-path 测不到。
func TestServerHandshakeV6Piggyback(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	const initial = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" // 模拟合并进命令 chunk 的首段
	errc := make(chan error, 1)
	go func() {
		cli := &snellv6.Client{PSK: testPSK}
		rc, err := cli.DialTCPOver(c, "example.com", 80, []byte(initial)) // piggyback 首段
		if err != nil {
			errc <- err
			return
		}
		if _, err := rc.Write([]byte("SECOND")); err != nil { // 后续段,验不错位
			errc <- err
			return
		}
		errc <- nil
	}()

	p := &Proxy{cfg: Config{PSK: testPSK}}
	stream, req, err := p.ServerHandshake(context.Background(), pipeStream{s}, testAuth{})
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst.String() != "example.com:80" {
		t.Fatalf("dst = %s", req.Dst.String())
	}
	// relay 首次读须先得到 piggyback 的 initial(逐字节完整、有序),再是 SECOND。
	want := initial + "SECOND"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("piggyback 数据丢失/错位:got %q, want %q", got, want)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// TestMultiUserByClientID:带 clientID 的命令 → 服务端解出 clientID → auth 映射到具名
// CredID(单端口 PSK + clientID 区分用户的 O(1) 多用户模型)。
func TestMultiUserByClientID(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	const clientID = "alice"
	aliceCred := cred.Ref{ID: cred.UserBase + 1}
	auth := testAuth{clientID: aliceCred}

	go func() { // 手工构造带 clientID 的 CONNECT 命令,经 Sender 加密发出
		snd := snellv6.NewSender(testPSK, false)
		cmd := []byte{1, snellv6.CmdConnect, byte(len(clientID))}
		cmd = append(cmd, clientID...)
		cmd = append(cmd, byte(len("host.example")))
		cmd = append(cmd, "host.example"...)
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], 8080)
		cmd = append(cmd, pb[:]...)
		enc, _ := snd.EncodeChunk(cmd)
		_, _ = c.Write(enc)
	}()

	p := &Proxy{cfg: Config{PSK: testPSK}}
	_, req, err := p.ServerHandshake(context.Background(), pipeStream{s}, auth)
	if err != nil {
		t.Fatal(err)
	}
	if req.Cred.ID != aliceCred.ID {
		t.Fatalf("CredID = %d, want %d (alice)", req.Cred.ID, aliceCred.ID)
	}
	if req.Dst.String() != "host.example:8080" {
		t.Fatalf("dst = %s", req.Dst.String())
	}
}
