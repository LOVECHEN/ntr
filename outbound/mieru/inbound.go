package mieru

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mieruconstant "github.com/enfein/mieru/v3/apis/constant"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mieruserver "github.com/enfein/mieru/v3/apis/server"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
)

// User 是 mieru 服务端用户(名 + 口令)。
type User struct {
	Name     string
	Password string
}

// Inbound 是 mieru 入站:用官方 apis/server 自绑端口(TCP/UDP 传输),Accept 每条代理连接后回
// socks5 成功应答(照 exampleapiserver 范式),再按目标路由到出站(或 dispatch 反连 portal)。
// 它自管监听(Run),不走 NTR 的 TCP 接入环 —— 与 hy2/tuic 自绑范式一致。
type Inbound struct {
	users     []User
	transport string // TCP | UDP
	out       endpoint.Outbound
	dispatch  endpoint.StreamDispatch
}

// NewInbound 构造 mieru 入站。dispatch 非 nil 时每条已握手流改派给它(反连 portal),否则 relay 到 out。
func NewInbound(users []User, transport string, out endpoint.Outbound, dispatch endpoint.StreamDispatch) (*Inbound, error) {
	if len(users) == 0 {
		return nil, fmt.Errorf("mieru: 入站需至少一个用户")
	}
	if transport == "" {
		transport = "TCP"
	}
	return &Inbound{users: users, transport: transport, out: out, dispatch: dispatch}, nil
}

// Run 启动 mieru 服务端(自绑 listenAddr 的端口)并循环 Accept,阻塞至 ctx 取消。
func (h *Inbound) Run(ctx context.Context, listenAddr string) error {
	_, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("mieru: listen 需 host:port:%w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("mieru: port:%w", err)
	}

	tp := mierupb.TransportProtocol_TCP.Enum()
	if h.transport == "UDP" {
		tp = mierupb.TransportProtocol_UDP.Enum()
	}
	users := make([]*mierupb.User, 0, len(h.users))
	for _, u := range h.users {
		users = append(users, &mierupb.User{Name: proto.String(u.Name), Password: proto.String(u.Password)})
	}

	srv := mieruserver.NewServer()
	if err := srv.Store(&mieruserver.ServerConfig{
		Config: &mierupb.ServerConfig{
			PortBindings: []*mierupb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: tp}},
			Users:        users,
		},
	}); err != nil {
		return fmt.Errorf("mieru: 存服务端配置:%w", err)
	}
	if err := srv.Start(); err != nil {
		return fmt.Errorf("mieru: 启动服务端:%w", err)
	}
	go func() {
		<-ctx.Done()
		_ = srv.Stop()
	}()

	for {
		conn, req, err := srv.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("mieru: accept:%w", err)
			}
		}
		go h.serve(ctx, conn, req)
	}
}

// serve 处理一条已 Accept 的 mieru 代理连接:TCP CONNECT 走流中继;UDP-ASSOCIATE 走 UDP 中继。
func (h *Inbound) serve(ctx context.Context, conn net.Conn, req *mierumodel.Request) {
	switch req.Command {
	case mieruconstant.Socks5ConnectCmd:
		h.serveTCP(ctx, conn, toNTRAddr(req))
	case mieruconstant.Socks5UDPAssociateCmd:
		h.serveUDP(ctx, conn)
	default:
		writeReply(conn, mieruconstant.Socks5ReplyCommandNotSupported)
		_ = conn.Close()
	}
}

// serveTCP:先按目标拨出站(失败回 failure),成功再回 socks5 success(客户端 STANDARD 握手在等它),
// 之后双向中继;dispatch 非 nil 则当反连 portal。
func (h *Inbound) serveTCP(ctx context.Context, conn net.Conn, dst addr.Socksaddr) {
	if h.dispatch != nil {
		writeReply(conn, mieruconstant.Socks5ReplySuccess)
		_ = h.dispatch(ctx, connStream{conn}, dst, endpoint.NetworkTCP)
		return
	}
	up, err := h.out.DialStream(ctx, dst)
	if err != nil {
		writeReply(conn, mieruconstant.Socks5ReplyServerFailure)
		_ = conn.Close()
		return
	}
	writeReply(conn, mieruconstant.Socks5ReplySuccess)
	_ = relay.Relay(connStream{conn}, up)
}

// serveUDP:UDP-over-tunnel 中继。回 success 后套 PacketOverStreamTunnel;上行读客户端 socks5-UDP
// 分帧包(目标+载荷)→ NTR 出站 DialPacket(多目标);下行把出站回包重新分帧回隧道。目标解析交给
// 出站(支持 FQDN),回包源恒 IP。
func (h *Inbound) serveUDP(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	writeReply(conn, mieruconstant.Socks5ReplySuccess)
	tunnel := mierucommon.NewPacketOverStreamTunnel(conn)

	var (
		mu     sync.Mutex
		pc     link.PacketConn
		dlOnce sync.Once
	)
	rbuf := make([]byte, 64*1024)
	for {
		n, _, err := tunnel.ReadFrom(rbuf)
		if err != nil {
			break
		}
		target, data, err := parseSocks5UDP(rbuf[:n])
		if err != nil {
			continue
		}
		mu.Lock()
		if pc == nil {
			pc, err = h.out.DialPacket(ctx, target)
			if err != nil {
				mu.Unlock()
				break
			}
			cur := pc
			dlOnce.Do(func() { go h.udpDownlink(cur, tunnel) })
		}
		cur := pc
		mu.Unlock()

		wb := buf.New()
		_, _ = wb.Write(data)
		if err := cur.WritePacket(wb, target); err != nil {
			break
		}
	}
	mu.Lock()
	if pc != nil {
		_ = pc.Close()
	}
	mu.Unlock()
}

// udpDownlink 把出站回包重新分帧([RSV2 FRAG ATYP src port][data])写回 mieru 隧道。
func (h *Inbound) udpDownlink(pc link.PacketConn, tunnel net.PacketConn) {
	for {
		b := buf.New()
		src, err := pc.ReadPacket(b)
		if err != nil {
			return
		}
		if _, err := tunnel.WriteTo(encodeSocks5UDP(src, b.Bytes()), nil); err != nil {
			return
		}
	}
}

// writeReply 回一条 socks5 应答(BindAddr 用 0.0.0.0:0,mieru 客户端不校验其值)。
func writeReply(conn net.Conn, reply byte) {
	resp := &mierumodel.Response{Reply: reply, BindAddr: mierumodel.AddrSpec{IP: net.IPv4zero, Port: 0}}
	_ = resp.WriteToSocks5(conn)
}

// toNTRAddr 把 mieru 请求目标转成 NTR Socksaddr(优先 FQDN)。
func toNTRAddr(req *mierumodel.Request) addr.Socksaddr {
	a := req.DstAddr
	if a.FQDN != "" {
		return addr.FromFqdn(a.FQDN, uint16(a.Port))
	}
	if ip, ok := netip.AddrFromSlice(a.IP); ok {
		return addr.FromIPPort(netip.AddrPortFrom(ip.Unmap(), uint16(a.Port)))
	}
	return addr.Socksaddr{}
}

// parseSocks5UDP 解客户端上行的 socks5-UDP 分帧包 [RSV(2) 00][FRAG 00][ATYP][addr][port][data],
// 返回目标 + 载荷(载荷为原缓冲切片,调用方随即拷入 buf)。
func parseSocks5UDP(b []byte) (addr.Socksaddr, []byte, error) {
	if len(b) < 4 {
		return addr.Socksaddr{}, nil, fmt.Errorf("mieru: UDP 包过短")
	}
	if b[2] != 0 {
		return addr.Socksaddr{}, nil, fmt.Errorf("mieru: 不支持 UDP 分片")
	}
	atyp := b[3]
	p := b[4:]
	var d addr.Socksaddr
	switch atyp {
	case 0x01:
		if len(p) < 4+2 {
			return d, nil, fmt.Errorf("mieru: UDP IPv4 头过短")
		}
		d.Addr = netip.AddrFrom4([4]byte(p[:4]))
		p = p[4:]
	case 0x04:
		if len(p) < 16+2 {
			return d, nil, fmt.Errorf("mieru: UDP IPv6 头过短")
		}
		d.Addr = netip.AddrFrom16([16]byte(p[:16]))
		p = p[16:]
	case 0x03:
		if len(p) < 1 {
			return d, nil, fmt.Errorf("mieru: UDP 域名头过短")
		}
		l := int(p[0])
		if len(p) < 1+l+2 {
			return d, nil, fmt.Errorf("mieru: UDP 域名头过短")
		}
		d.Fqdn = string(p[1 : 1+l])
		p = p[1+l:]
	default:
		return d, nil, fmt.Errorf("mieru: UDP 未知 ATYP %d", atyp)
	}
	d.Port = binary.BigEndian.Uint16(p[:2])
	return d, p[2:], nil
}

// encodeSocks5UDP 把出站回包封成 socks5-UDP 分帧([RSV2 FRAG ATYP src port][data]),回写隧道。
func encodeSocks5UDP(src addr.Socksaddr, data []byte) []byte {
	out := []byte{0, 0, 0}
	switch {
	case src.IsFqdn():
		out = append(out, 0x03, byte(len(src.Fqdn)))
		out = append(out, src.Fqdn...)
	case src.Addr.Is4():
		out = append(out, 0x01)
		a := src.Addr.As4()
		out = append(out, a[:]...)
	default:
		out = append(out, 0x04)
		a := src.Addr.As16()
		out = append(out, a[:]...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], src.Port)
	out = append(out, pb[:]...)
	return append(out, data...)
}

var _ link.Stream = connStream{}
