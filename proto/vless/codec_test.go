package vless

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/cred"
)

// golden:请求头 = 00 |11×16| 00(addonLen) | 01(TCP) | 01BB(port 443) | 02 0B(domain,len11) | "example.com"
// 逐字节对齐 Xray proxy/vless/encoding 的布局(PortThenAddress、atyp domain=0x02)。
const goldenReqHex = "00" +
	"11111111111111111111111111111111" +
	"00" + "01" + "01bb" + "020b" + "6578616d706c652e636f6d"

func demoReq() RequestHeader {
	var u [16]byte
	for i := range u {
		u[i] = 0x11
	}
	return RequestHeader{UUID: u, Command: CmdTCP, Dst: addr.FromFqdn("example.com", 443)}
}

func TestEncodeGolden(t *testing.T) {
	want, _ := hex.DecodeString(goldenReqHex)
	b := buf.New()
	defer b.Release()
	if err := (RequestCodec{}).Encode(b, demoReq()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("encode mismatch\n got=%x\nwant=%x", b.Bytes(), want)
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	wire, _ := hex.DecodeString(goldenReqHex)
	got, err := (RequestCodec{}).Decode(buf.As(append([]byte(nil), wire...)))
	if err != nil {
		t.Fatal(err)
	}
	want := demoReq()
	if got.UUID != want.UUID || got.Command != want.Command ||
		got.Dst.Fqdn != "example.com" || got.Dst.Port != 443 {
		t.Fatalf("decoded %+v", got)
	}
}

func TestDecodeIPv4(t *testing.T) {
	var u [16]byte
	req := RequestHeader{UUID: u, Command: CmdTCP, Dst: mustAddr("1.2.3.4", 8443)}
	b := buf.New()
	defer b.Release()
	if err := (RequestCodec{}).Encode(b, req); err != nil {
		t.Fatal(err)
	}
	got, err := (RequestCodec{}).Decode(buf.As(append([]byte(nil), b.Bytes()...)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Dst.String() != "1.2.3.4:8443" {
		t.Fatalf("ipv4 dst = %s", got.Dst.String())
	}
}

// TestServerClientHandshakePipe:经统一的 proxy.Server/proxy.Client 接口端到端握手
// (含响应头:服务端写 / 客户端 strip)+ 双向 payload + UUID→凭据归属。
func TestServerClientHandshakePipe(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	p := &Proxy{}
	var uuid [16]byte
	for i := range uuid {
		uuid[i] = byte(i)
	}
	dst := addr.FromFqdn("target.example", 443)
	auth := testAuth{uuid: uuid, ref: cred.Ref{ID: cred.UserBase + 7}}
	ctx := context.Background()

	errc := make(chan error, 1)
	go func() {
		cs, err := p.ClientHandshake(ctx, pipeStream{c}, uuid[:], dst)
		if err != nil {
			errc <- err
			return
		}
		if _, err := cs.Write([]byte("PAYLOAD")); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(cs, buf); err != nil {
			errc <- err
			return
		}
		if string(buf) != "PONG" {
			errc <- fmt.Errorf("client got %q", buf)
			return
		}
		errc <- nil
	}()

	ss, req, err := p.ServerHandshake(ctx, pipeStream{s}, auth)
	if err != nil {
		t.Fatal(err)
	}
	if req.Cred.ID != cred.UserBase+7 {
		t.Fatalf("cred = %d, want %d", req.Cred.ID, cred.UserBase+7)
	}
	if req.Dst.Fqdn != "target.example" || req.Dst.Port != 443 {
		t.Fatalf("server dst = %+v", req.Dst)
	}
	pl := make([]byte, 7)
	if _, err := io.ReadFull(ss, pl); err != nil {
		t.Fatal(err)
	}
	if string(pl) != "PAYLOAD" {
		t.Fatalf("payload = %q", pl)
	}
	if _, err := ss.Write([]byte("PONG")); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestServerHandshakeUnknownUserLoud(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	p := &Proxy{}
	ctx := context.Background()
	unknown := bytes.Repeat([]byte{0x99}, 16) // testAuth{}(零 uuid)不认它
	go func() { _, _ = p.ClientHandshake(ctx, pipeStream{c}, unknown, addr.FromFqdn("x", 1)) }()
	// auth 拒绝 → 服务端必须大声报,不静默放行。
	if _, _, err := p.ServerHandshake(ctx, pipeStream{s}, testAuth{}); err == nil {
		t.Fatal("expected loud error for unknown user id")
	}
}

func TestClientHandshakeFlowLoud(t *testing.T) {
	c, _ := net.Pipe()
	defer c.Close()
	p := &Proxy{cfg: Config{Flow: "xtls-rprx-vision"}}
	if _, err := p.ClientHandshake(context.Background(), pipeStream{c}, make([]byte, 16), addr.FromFqdn("x", 1)); err == nil {
		t.Fatal("expected loud error for unimplemented flow")
	}
}

func mustAddr(ip string, port uint16) addr.Socksaddr {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		panic(err)
	}
	return addr.Socksaddr{Addr: a, Port: port}
}

// pipeStream 把 net.Conn 包成 link.Stream(补 Unwrap)。
type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

// testAuth 是最小 Authenticator:只认一个 UUID。
type testAuth struct {
	uuid [16]byte
	ref  cred.Ref
}

func (a testAuth) Auth(scheme string, key []byte) (cred.Ref, bool) {
	if scheme == "vless" && len(key) == 16 && [16]byte(key) == a.uuid {
		return a.ref, true
	}
	return cred.Ref{}, false
}
