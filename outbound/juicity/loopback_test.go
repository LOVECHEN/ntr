package juicity

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
	"github.com/LOVECHEN/ntr/outbound/direct"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// startServer 起一个回环 Juicity 服务端:TCP 直出 direct,UDP 交给 full-cone direct(单 socket 多目标、回真实来源)。
func startServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	inb, err := NewInbound(InboundOptions{
		Users: []User{{Name: "alice", UUID: testUUID, Password: "pw"}},
		TLS:   &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}},
		Out:   direct.Outbound{},
		PacketDispatch: func(ctx context.Context, cli link.PacketConn) error {
			up, err := direct.Outbound{FullCone: true}.DialPacket(ctx, addr.Socksaddr{})
			if err != nil {
				_ = cli.Close()
				return err
			}
			return relay.RelayPacket(cli, up)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = inb.Serve(ctx, pc) }()
	return pc.LocalAddr().String()
}

func tcpEcho(t *testing.T) addr.Socksaddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return addr.FromIPPort(netip.MustParseAddrPort(ln.Addr().String()))
}

func udpEcho(t *testing.T) addr.Socksaddr {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = uc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := uc.ReadFromUDP(b)
			if err != nil {
				return
			}
			_, _ = uc.WriteToUDP(b[:n], from)
		}
	}()
	return addr.FromIPPort(netip.MustParseAddrPort(uc.LocalAddr().String()))
}

func newClient(t *testing.T, server, password string) *Outbound {
	t.Helper()
	o, err := NewOutbound(Options{Server: server, UUID: testUUID, Password: password, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func echoOnce(t *testing.T, o *Outbound, dst addr.Socksaddr, msg string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := o.DialStream(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatalf("读回显: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("回显 %q 期望 %q", got, msg)
	}
}

func TestLoopbackTCP(t *testing.T) {
	srv := startServer(t)
	o := newClient(t, srv, "pw")
	echoOnce(t, o, tcpEcho(t), "hello juicity")
}

func TestWrongPasswordRejected(t *testing.T) {
	srv := startServer(t)
	o := newClient(t, srv, "WRONG")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := o.DialStream(ctx, tcpEcho(t))
	if err != nil {
		return // 连接已被关:同样算拒绝
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(4 * time.Second))
	_, _ = s.Write([]byte("x"))
	b := make([]byte, 1)
	if n, err := s.Read(b); err == nil && n > 0 {
		t.Fatal("错密码竟拿到回显")
	}
}

// UDP:同一条代理流发往两个不同目标,各自回显且来源地址正确(多目标 + 帧边界 + 来源回写)。
func TestLoopbackUDPMultiTarget(t *testing.T) {
	srv := startServer(t)
	o := newClient(t, srv, "pw")
	e1, e2 := udpEcho(t), udpEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := o.DialPacket(ctx, e1)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	send := func(dst addr.Socksaddr, msg string) {
		b := buf.New()
		defer b.Release()
		_, _ = b.Write([]byte(msg))
		if err := pc.WritePacket(b, dst); err != nil {
			t.Fatal(err)
		}
	}
	send(e1, "to-one")
	send(e2, "to-two")
	got := map[string]string{}
	for i := 0; i < 2; i++ {
		b := buf.New()
		src, err := pc.ReadPacket(b)
		if err != nil {
			t.Fatalf("读 UDP 回显: %v", err)
		}
		got[src.String()] = string(b.Bytes())
		b.Release()
	}
	if got[e1.String()] != "to-one" || got[e2.String()] != "to-two" {
		t.Fatalf("多目标回显错: %v(期望 %s→to-one, %s→to-two)", got, e1, e2)
	}
}

// 连续开 35 条流:超过 30 条后须换新连接(规范),且每条都正常回显。
func TestStreamRotation(t *testing.T) {
	srv := startServer(t)
	o := newClient(t, srv, "pw")
	dst := tcpEcho(t)
	echoOnce(t, o, dst, "first")
	o.mu.Lock()
	first := o.cur.conn
	o.mu.Unlock()
	for i := 0; i < maxStreamsPerConn+4; i++ {
		echoOnce(t, o, dst, "rot")
	}
	o.mu.Lock()
	now := o.cur.conn
	o.mu.Unlock()
	if now == first {
		t.Fatal("开满 30 条流后未换新连接")
	}
}
