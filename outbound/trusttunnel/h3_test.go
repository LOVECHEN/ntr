package trusttunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/internal/selfcert"
	"github.com/LOVECHEN/ntr/outbound/anytls"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/service"
)

// TestH3RoundTrip:出站 quic: true → 入站 H3(ServePacket 跑在 UDP 上),普通 CONNECT 的 TCP 隧道与 _udp2
// 帧复用都经 HTTP/3 往返;错口令被拒。
func TestH3RoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tcpEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	go func() {
		for {
			c, err := tcpEcho.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()
	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, err := udpEcho.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteTo(b[:n], from)
		}
	}()

	tlsConf, err := anytls.ServerTLSConfig("", "")
	if err != nil {
		t.Fatal(err)
	}
	inb, err := NewInbound([]User{{Name: "u", Password: "pw"}}, tlsConf, direct.Outbound{}, nil,
		service.SessionPacketDispatch(direct.Outbound{}, nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	h3TLS, err := selfcert.Metacubex("", "")
	if err != nil {
		t.Fatal(err)
	}
	inb.EnableH3(h3TLS)
	if !inb.SupportsNativePacket() {
		t.Fatal("开 H3 后应要求同址 UDP 监听")
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = inb.ServePacket(ctx, pc) }()

	out, err := NewOutbound(Options{Server: pc.LocalAddr().String(), User: "u", Password: "pw", SNI: "localhost", Insecure: true, QUIC: true})
	if err != nil {
		t.Fatal(err)
	}

	// TCP:普通 CONNECT over H3
	st, err := out.DialStream(ctx, addr.FromIPPort(tcpEcho.Addr().(*net.TCPAddr).AddrPort()))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("tt-over-h3-tcp")
	if _, err := st.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(st, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("H3 TCP 回显不符:%q %v", got, err)
	}
	_ = st.Close()

	// UDP:_udp2 over H3
	upc, err := out.DialPacket(ctx, addr.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer upc.Close()
	dst := addr.FromIPPort(udpEcho.LocalAddr().(*net.UDPAddr).AddrPort())
	ok := false
	for i := 0; i < 5 && !ok; i++ {
		if err := upc.WritePacket(buf.As([]byte("tt-over-h3-udp")), dst); err != nil {
			t.Fatal(err)
		}
		_ = upc.SetDeadline(time.Now().Add(2 * time.Second))
		b := buf.New()
		from, err := upc.ReadPacket(b)
		if err == nil {
			if string(b.Bytes()) != "tt-over-h3-udp" || from.Port != dst.Port {
				t.Fatalf("H3 UDP 回显不符:%q from %v", b.Bytes(), from)
			}
			ok = true
		}
		b.Release()
	}
	if !ok {
		t.Fatal("H3 _udp2 往返多次超时")
	}

	// 错口令
	bad, err := NewOutbound(Options{Server: pc.LocalAddr().String(), User: "u", Password: "nope", SNI: "localhost", Insecure: true, QUIC: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.DialStream(ctx, addr.FromIPPort(tcpEcho.Addr().(*net.TCPAddr).AddrPort())); err == nil {
		t.Fatal("错口令应被 407 拒绝")
	}
}
