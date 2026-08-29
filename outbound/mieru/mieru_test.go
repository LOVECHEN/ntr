package mieru

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mieruconstant "github.com/enfein/mieru/v3/apis/constant"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mieruserver "github.com/enfein/mieru/v3/apis/server"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

// freePort 抢一个空闲 TCP 端口号(关掉监听后交给 mieru 服务端自绑;测试内轻量,竞态可忽略)。
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

// TestMieruSelfLoop:用 mieru 官方 apis/server 起一个真服务端(echo),NTR mieru 出站客户端拨一条流,
// 往返一段数据验证客户端与官方服务端库线级互通(同一 enfein/mieru 库,禁改线格式)。-race 干净。
func TestMieruSelfLoop(t *testing.T) {
	const user, pass = "loopuser", "looppass123"
	port := freePort(t)

	srv := mieruserver.NewServer()
	err := srv.Store(&mieruserver.ServerConfig{
		Config: &mierupb.ServerConfig{
			PortBindings: []*mierupb.PortBinding{
				{Port: proto.Int32(int32(port)), Protocol: mierupb.TransportProtocol_TCP.Enum()},
			},
			Users: []*mierupb.User{{Name: proto.String(user), Password: proto.String(pass)}},
		},
	})
	if err != nil {
		t.Fatalf("server store:%v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("server start:%v", err)
	}
	defer srv.Stop()

	// 服务端 Accept 环:每条代理连接就地 echo(忽略请求目标,只验隧道承载)。
	go func() {
		for {
			conn, _, err := srv.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// 官方服务端范式:Accept 后须先回 socks5 成功应答,再中继/echo。
				resp := &mierumodel.Response{
					Reply:    mieruconstant.Socks5ReplySuccess,
					BindAddr: mierumodel.AddrSpec{IP: net.IPv4zero, Port: 0},
				}
				if err := resp.WriteToSocks5(c); err != nil {
					return
				}
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	time.Sleep(300 * time.Millisecond) // 等服务端端口就绪

	out, err := NewOutbound(Options{Server: "127.0.0.1:" + itoa(port), Transport: "TCP", Username: user, Password: pass})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := out.DialStream(ctx, addr.FromFqdn("echo.target", 1234))
	if err != nil {
		t.Fatalf("DialStream:%v", err)
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(6 * time.Second))

	msg := []byte("mieru-selfloop-hello-42")
	if _, err := s.Write(msg); err != nil {
		t.Fatalf("write:%v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatalf("read:%v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo 不符:got %q want %q", got, msg)
	}
}

// dialOutbound 是测试用极简出站:直接 net.Dial 到目标(NTR mieru 服务端据此把解出的目标落地)。
type dialOutbound struct{}

func (dialOutbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, err
	}
	return connStream{c}, nil
}
func (dialOutbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, io.EOF
}

// TestMieruInboundRoundTrip:NTR mieru 客户端 → NTR mieru 服务端 → echo,全链路往返。
// 证 NTR 自身 mieru 客户端/服务端两侧线级自洽(叠加对 mihomo 的交叉验证 = 双向闭合)。-race 干净。
func TestMieruInboundRoundTrip(t *testing.T) {
	const user, pass = "inuser", "inpass456"

	// 本地 echo 服务端(mieru 服务端解出的目标)。
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()

	// NTR mieru 入站(自绑端口),路由到 dialOutbound。
	mieruPort := freePort(t)
	inb, err := NewInbound([]User{{Name: user, Password: pass}}, "TCP", dialOutbound{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = inb.Run(ctx, "127.0.0.1:"+itoa(mieruPort)) }()
	time.Sleep(400 * time.Millisecond)

	// NTR mieru 出站 → NTR mieru 入站。
	out, err := NewOutbound(Options{Server: "127.0.0.1:" + itoa(mieruPort), Transport: "TCP", Username: user, Password: pass})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dcancel()
	s, err := out.DialStream(dctx, mustAddr(echoLn.Addr().String()))
	if err != nil {
		t.Fatalf("DialStream:%v", err)
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(6 * time.Second))

	msg := []byte("ntr-mieru-c2s-roundtrip-99")
	if _, err := s.Write(msg); err != nil {
		t.Fatalf("write:%v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatalf("read:%v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo 不符:got %q want %q", got, msg)
	}
}

// mustAddr 把 "127.0.0.1:port" 转成 NTR Socksaddr。
func mustAddr(hostport string) addr.Socksaddr {
	ap, _ := netip.ParseAddrPort(hostport)
	return addr.FromIPPort(ap)
}

// echoUDPOutbound 的 DialPacket 返回内存 echo PacketConn:WritePacket 存 (dst,data),ReadPacket 原样取回。
type echoUDPOutbound struct{}

func (echoUDPOutbound) DialStream(context.Context, addr.Socksaddr) (link.Stream, error) {
	return nil, io.EOF
}
func (echoUDPOutbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return &echoPacketConn{ch: make(chan echoPkt, 16), closed: make(chan struct{})}, nil
}

type echoPkt struct {
	dst  addr.Socksaddr
	data []byte
}
type echoPacketConn struct {
	ch     chan echoPkt
	closed chan struct{}
	once   sync.Once
}

func (c *echoPacketConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	select {
	case p := <-c.ch:
		b.Reset()
		_, _ = b.Write(p.data)
		return p.dst, nil
	case <-c.closed:
		return addr.Socksaddr{}, io.EOF
	}
}
func (c *echoPacketConn) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	d := append([]byte(nil), b.Bytes()...)
	select {
	case c.ch <- echoPkt{dst: dst, data: d}:
		return nil
	case <-c.closed:
		return io.EOF
	}
}
func (c *echoPacketConn) Close() error                  { c.once.Do(func() { close(c.closed) }); return nil }
func (c *echoPacketConn) LocalAddr() net.Addr           { return &net.UDPAddr{} }
func (c *echoPacketConn) SetDeadline(t time.Time) error { return nil }
func (c *echoPacketConn) Unwrap() any                   { return nil }

var _ link.PacketConn = (*echoPacketConn)(nil)

// TestMieruInboundUDPRoundTrip:NTR mieru 出站 DialPacket → NTR mieru 入站 serveUDP → 内存 echo,
// 验 NTR 自身 mieru UDP 载荷两侧(出站 DialPacket + 入站 serveUDP)线级自洽。-race 干净。
func TestMieruInboundUDPRoundTrip(t *testing.T) {
	const user, pass = "inudpuser", "inudppass"
	mieruPort := freePort(t)
	inb, err := NewInbound([]User{{Name: user, Password: pass}}, "TCP", echoUDPOutbound{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = inb.Run(ctx, "127.0.0.1:"+itoa(mieruPort)) }()
	time.Sleep(400 * time.Millisecond)

	out, err := NewOutbound(Options{Server: "127.0.0.1:" + itoa(mieruPort), Transport: "TCP", Username: user, Password: pass})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	target, _ := netip.ParseAddrPort("192.0.2.9:1234")
	dst := addr.FromIPPort(target)
	dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dcancel()
	pc, err := out.DialPacket(dctx, dst)
	if err != nil {
		t.Fatalf("DialPacket:%v", err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(6 * time.Second))

	msg := []byte("ntr-mieru-udp-inbound-88")
	wb := buf.New()
	_, _ = wb.Write(msg)
	if err := pc.WritePacket(wb, dst); err != nil {
		t.Fatalf("WritePacket:%v", err)
	}
	rb := buf.New()
	src, err := pc.ReadPacket(rb)
	if err != nil {
		t.Fatalf("ReadPacket:%v", err)
	}
	if string(rb.Bytes()) != string(msg) {
		t.Fatalf("UDP echo 不符:got %q want %q", rb.Bytes(), msg)
	}
	if src.Addr != dst.Addr || src.Port != dst.Port {
		t.Fatalf("源地址不符:got %v want %v", src, dst)
	}
}

// TestMieruUDPSelfLoop:NTR mieru 出站 DialPacket(UDP-over-tunnel)→ 官方 apis/server(UDP-associate,
// 帧级 echo)→ 往返一个 UDP 载荷,验客户端 UDP 路径(PacketOverStreamTunnel+UDPAssociateWrapper 适配)
// 与官方服务端库线级互通。-race 干净。
func TestMieruUDPSelfLoop(t *testing.T) {
	const user, pass = "udpuser", "udppass789"
	port := freePort(t)

	srv := mieruserver.NewServer()
	if err := srv.Store(&mieruserver.ServerConfig{
		Config: &mierupb.ServerConfig{
			PortBindings: []*mierupb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: mierupb.TransportProtocol_TCP.Enum()}},
			Users:        []*mierupb.User{{Name: proto.String(user), Password: proto.String(pass)}},
		},
	}); err != nil {
		t.Fatalf("server store:%v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("server start:%v", err)
	}
	defer srv.Stop()

	go func() {
		for {
			conn, req, err := srv.Accept()
			if err != nil {
				return
			}
			if req.Command != mieruconstant.Socks5UDPAssociateCmd {
				_ = conn.Close()
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				resp := &mierumodel.Response{Reply: mieruconstant.Socks5ReplySuccess, BindAddr: mierumodel.AddrSpec{IP: net.IPv4zero, Port: 0}}
				if err := resp.WriteToSocks5(c); err != nil {
					return
				}
				// 帧级 echo:PacketOverStreamTunnel 读回一整个 socks5-framed 包,原样写回。
				tunnel := mierucommon.NewPacketOverStreamTunnel(c)
				b := make([]byte, 64*1024)
				for {
					n, _, err := tunnel.ReadFrom(b)
					if err != nil {
						return
					}
					if _, err := tunnel.WriteTo(b[:n], nil); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	time.Sleep(300 * time.Millisecond)

	out, err := NewOutbound(Options{Server: "127.0.0.1:" + itoa(port), Transport: "TCP", Username: user, Password: pass})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	// UDP 目标须为 IP(mieru UDPAssociateWrapper 回读不接受 FQDN)。
	target, err := netip.ParseAddrPort("192.0.2.7:5353")
	if err != nil {
		t.Fatal(err)
	}
	dst := addr.FromIPPort(target)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := out.DialPacket(ctx, dst)
	if err != nil {
		t.Fatalf("DialPacket:%v", err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(6 * time.Second))

	msg := []byte("mieru-udp-payload-77")
	wb := buf.New()
	_, _ = wb.Write(msg)
	if err := pc.WritePacket(wb, dst); err != nil {
		t.Fatalf("WritePacket:%v", err)
	}
	rb := buf.New()
	src, err := pc.ReadPacket(rb)
	if err != nil {
		t.Fatalf("ReadPacket:%v", err)
	}
	if string(rb.Bytes()) != string(msg) {
		t.Fatalf("UDP echo 不符:got %q want %q", rb.Bytes(), msg)
	}
	if src.Addr != dst.Addr || src.Port != dst.Port {
		t.Fatalf("回读源地址不符:got %v want %v", src, dst)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
