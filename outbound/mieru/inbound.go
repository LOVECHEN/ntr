package mieru

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

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
	"github.com/LOVECHEN/ntr/internal/ipresolve"
)

// User 是 mieru 服务端用户(名 + 口令)。
type User struct {
	Name     string
	Password string
}

type ctxUserKey struct{}

// withUser 把认证到的计费用户名挂进 ctx(mieru accepted conn 自带 UserContext.UserName())。
func withUser(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, ctxUserKey{}, name)
}

// UserFromContext 读认证命中的计费用户名(供 config 的 SessionDispatch 回读 → cred.ID 计量)。
func UserFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(ctxUserKey{}).(string)
	return name, ok && name != ""
}

// Inbound 是 mieru 入站:用官方 apis/server 自绑端口(TCP/UDP 传输),Accept 每条代理连接后回
// socks5 成功应答(照 exampleapiserver 范式),再按目标路由到出站(或 dispatch 反连 portal)。
// 它自管监听(Run),不走 NTR 的 TCP 接入环 —— 与 hy2/tuic 自绑范式一致。
type Inbound struct {
	users     []User
	transport string // TCP | UDP
	out       endpoint.Outbound
	dispatch  endpoint.StreamDispatch
	packet    endpoint.PacketDispatch
}

// NewInbound 构造 mieru 入站。dispatch 非 nil 时每条已握手流改派给它(计量 / 反连 portal),否则 relay 到 out。
// packet 接手 UDP-ASSOCIATE 会话(运行时按包目标路由 + 准入计量;portal 口桥进隧道);nil = 拒 UDP。
func NewInbound(users []User, transport string, out endpoint.Outbound, dispatch endpoint.StreamDispatch, packet endpoint.PacketDispatch) (*Inbound, error) {
	if len(users) == 0 {
		return nil, fmt.Errorf("mieru: 入站需至少一个用户")
	}
	if transport == "" {
		transport = "TCP"
	}
	return &Inbound{users: users, transport: transport, out: out, dispatch: dispatch, packet: packet}, nil
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
// accepted conn 实现 UserContext,取认证到的计费用户名挂进 ctx(供 dispatch 计量回读)。
func (h *Inbound) serve(ctx context.Context, conn net.Conn, req *mierumodel.Request) {
	if uc, ok := conn.(mierucommon.UserContext); ok {
		if name := uc.UserName(); name != "" {
			ctx = withUser(ctx, name)
		}
	}
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

// serveUDP:UDP-over-tunnel。回 success 后套 PacketOverStreamTunnel,包成多目标 link.PacketConn
// (每包 socks5-UDP 分帧自带目标)交运行时 PacketDispatch —— 逐包按目标路由、回包按真实来源回写、
// 准入 + 计量随身份(ctx)走;portal 口整条会话桥进隧道。
func (h *Inbound) serveUDP(ctx context.Context, conn net.Conn) {
	if h.packet == nil {
		writeReply(conn, mieruconstant.Socks5ReplyCommandNotSupported)
		_ = conn.Close()
		return
	}
	writeReply(conn, mieruconstant.Socks5ReplySuccess)
	_ = h.packet(ctx, &tunnelPacketConn{conn: conn, tunnel: mierucommon.NewPacketOverStreamTunnel(conn)})
}

// tunnelPacketConn 把 mieru 的 UDP-over-tunnel(socks5-UDP 分帧)适配成 link.PacketConn(服务端侧客户端连接):
// ReadPacket 解出目标 + 载荷;WritePacket 以回包来源分帧写回。写并发安全(运行时多目标回写会并发)。
type tunnelPacketConn struct {
	conn   net.Conn
	tunnel net.PacketConn
	wmu    sync.Mutex
	rbuf   [64 * 1024]byte
	ips    ipresolve.Cache // 回包头只许 IP(官方客户端拒 FQDN):目标以域名进来时回包来源须还原成 IP
}

var _ link.PacketConn = (*tunnelPacketConn)(nil)

func (c *tunnelPacketConn) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	for {
		n, _, err := c.tunnel.ReadFrom(c.rbuf[:])
		if err != nil {
			return addr.Socksaddr{}, err
		}
		target, data, err := parseSocks5UDP(c.rbuf[:n])
		if err != nil || len(data) > b.Tailroom() { // 坏帧 / 超缓冲:丢弃,读下一个(保包边界)
			continue
		}
		copy(b.ExtendTail(len(data)), data)
		return target, nil
	}
}

func (c *tunnelPacketConn) WritePacket(b *buf.Buffer, src addr.Socksaddr) error {
	ipSrc, err := c.ips.Resolve(src)
	if err != nil { // 解析不出(极少:目标域名本机查不到而上游能通)→ 以 0.0.0.0 标注来源,不丢包
		ipSrc = addr.FromIPPort(netip.AddrPortFrom(netip.IPv4Unspecified(), src.Port))
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.tunnel.WriteTo(encodeSocks5UDP(ipSrc, b.Bytes()), nil)
	return err
}

func (c *tunnelPacketConn) Close() error                  { return c.conn.Close() }
func (c *tunnelPacketConn) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *tunnelPacketConn) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *tunnelPacketConn) SetDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }
func (c *tunnelPacketConn) Unwrap() any                   { return nil }

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
