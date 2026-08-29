package masque

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/outbound/hysteria2"
)

// TestConnectUDPPathRoundTrip:RFC 9298 URI 模板生成 → 解析往返一致,含 IPv6 冒号 %3A 转义。
func TestConnectUDPPathRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		dst  addr.Socksaddr
	}{
		{"域名", addr.FromFqdn("example.com", 53)},
		{"IPv4", mustAddr(t, "192.0.2.1", 443)},
		{"IPv6", mustAddr(t, "2001:db8::42", 5353)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, esc := connectUDPPath(c.dst)
			// IPv6 的转义版必须把冒号变成 %3A(RFC 9298 §3)
			if c.dst.Addr.IsValid() && c.dst.Addr.Is6() {
				if bytes.Contains([]byte(esc), []byte(":")) {
					t.Fatalf("IPv6 转义版仍含裸冒号:%s", esc)
				}
			}
			// 服务端拿到的是解码后的 path(即 raw),解析应还原目标
			got, err := parseConnectUDPPath(raw)
			if err != nil {
				t.Fatalf("解析 %q 失败:%v", raw, err)
			}
			if got.String() != c.dst.String() {
				t.Fatalf("往返不一致:得到 %s,want %s(path=%s)", got, c.dst, raw)
			}
		})
	}
}

// TestParseConnectUDPPathReject:畸形模板路径应被拒。
func TestParseConnectUDPPathReject(t *testing.T) {
	bad := []string{
		"/wrong/prefix/host/53/",
		"/.well-known/masque/udp/",          // 缺 host/port
		"/.well-known/masque/udp/host/",     // 缺 port
		"/.well-known/masque/udp/host/0/",   // 端口 0 非法(RFC:1–65535)
		"/.well-known/masque/udp/host/abc/", // 端口非数字
	}
	for _, p := range bad {
		if _, err := parseConnectUDPPath(p); err == nil {
			t.Errorf("期望拒绝 %q,但通过了", p)
		}
	}
}

// TestContextID:RFC 9298 的 Context-ID 编解码 —— 0 有效、非 0 丢弃。
func TestContextID(t *testing.T) {
	payload := []byte("udp-payload")
	wire := prependContextID(payload)
	if wire[0] != 0x00 {
		t.Fatalf("Context-ID 0 应编成单字节 0x00,得到 %#x", wire[0])
	}
	got, ok := stripContextID(wire)
	if !ok || !bytes.Equal(got, payload) {
		t.Fatalf("往返失败:ok=%v got=%q want=%q", ok, got, payload)
	}
	// 非零 Context-ID 未协商 → 必须丢弃(RFC 9298 §5)
	if _, ok := stripContextID([]byte{0x01, 'x'}); ok {
		t.Error("非零 Context-ID 应被丢弃")
	}
	if _, ok := stripContextID(nil); ok {
		t.Error("空 datagram 应被丢弃")
	}
}

// TestMasqueRoundTrip:NTR masque 客户端 → 服务端(QUIC/h3)→ direct,TCP 与 UDP 双通道往返。
func TestMasqueRoundTrip(t *testing.T) {
	// TCP echo 靶
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
	// UDP echo 靶
	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		p := make([]byte, 2048)
		for {
			n, from, err := udpEcho.ReadFrom(p)
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteTo(p[:n], from)
		}
	}()

	// MASQUE 服务端(QUIC/h3,临时自签证书)
	tlsConfig, err := hysteria2.ServerTLSConfig("", "")
	if err != nil {
		t.Fatal(err)
	}
	inb, err := NewInbound(nil, tlsConfig, direct.Outbound{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 先占一个空闲 UDP 端口拿地址,再关掉交给 Run 绑
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvAddr := probe.LocalAddr().String()
	_ = probe.Close()
	go func() { _ = inb.Run(ctx, srvAddr) }()
	time.Sleep(300 * time.Millisecond) // 等监听就绪

	out, err := NewOutbound(Options{Server: srvAddr, SNI: "localhost", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	t.Run("TCP-over-h3-CONNECT", func(t *testing.T) {
		dst := addr.FromIPPort(tcpEcho.Addr().(*net.TCPAddr).AddrPort())
		st, err := out.DialStream(context.Background(), dst)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		msg := []byte("hello-masque-tcp")
		if _, err := st.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(st, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("TCP echo 不匹配:%q != %q", got, msg)
		}
	})

	t.Run("UDP-over-connect-udp", func(t *testing.T) {
		dst := addr.FromIPPort(udpEcho.LocalAddr().(*net.UDPAddr).AddrPort())
		pc, err := out.DialPacket(context.Background(), dst)
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		msg := []byte("hello-masque-udp")
		wb := buf.New()
		defer wb.Release()
		if _, err := wb.Write(msg); err != nil {
			t.Fatal(err)
		}
		if err := pc.WritePacket(wb, dst); err != nil {
			t.Fatal(err)
		}
		done := make(chan []byte, 1)
		go func() {
			rb := buf.New()
			defer rb.Release()
			if _, err := pc.ReadPacket(rb); err != nil {
				done <- nil
				return
			}
			done <- append([]byte(nil), rb.Bytes()...)
		}()
		select {
		case got := <-done:
			if !bytes.Equal(got, msg) {
				t.Fatalf("UDP echo 不匹配:%q != %q", got, msg)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("等 UDP 回显超时")
		}
	})
}

func mustAddr(t *testing.T, ip string, port uint16) addr.Socksaddr {
	t.Helper()
	sa, err := parseHostPort(net.JoinHostPort(ip, itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	return sa
}

func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
