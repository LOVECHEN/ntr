package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing/common/metadata"

	"golang.org/x/crypto/ssh"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/relay"
)

var _ endpoint.InboundHandler = (*Inbound)(nil)

// userExt 是认证回调写进 ssh.Permissions.Extensions 的键(值=计费用户名)。
const userExt = "ntr-user"

type ctxUserKey struct{}

// withUser 把认证到的计费用户名挂进 ctx(SSH 每连接认证一次,该连接所有 channel 共享)。
func withUser(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, ctxUserKey{}, name)
}

// UserFromContext 读认证命中的计费用户名(供 config 的 SessionDispatch 回读 → cred.ID 计量)。
func UserFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(ctxUserKey{}).(string)
	return name, ok && name != ""
}

// User 是 SSH 服务端用户(名 + 密码 或 授权公钥,至少其一)。
type User struct {
	Name      string
	Password  string // 密码认证(可空)
	PublicKey string // authorized_keys 单行(公钥认证,可空)
}

// Inbound 是 SSH 会话解复用入站:一条 TCP 连接 → SSH server 握手 → 多条 direct-tcpip channel,
// 每条按其目标路由到出站。NTR 管 TCP 监听(InboundHandler),SSH 握手/解复用在拿到的 stream 上做。
type Inbound struct {
	config   *ssh.ServerConfig
	out      endpoint.Outbound
	dispatch endpoint.StreamDispatch
}

// NewInbound 构造 SSH 入站(host 私钥 PEM + 用户 + 绑定出站)。dispatch 非 nil 时每条 channel 改派
// 给它(反连 portal),否则 relay 到 out。
func NewInbound(users []User, hostKeyPEM string, out endpoint.Outbound, dispatch endpoint.StreamDispatch) (*Inbound, error) {
	signer, err := ssh.ParsePrivateKey([]byte(hostKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("ssh: 解析 host 私钥失败:%w", err)
	}
	pwUsers := map[string]string{}  // name → password
	keyUsers := map[string]string{} // marshaled authorized key → 计费用户名(计量归属)
	for _, u := range users {
		if u.Password != "" {
			pwUsers[u.Name] = u.Password
		}
		if u.PublicKey != "" {
			pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(u.PublicKey))
			if err != nil {
				return nil, fmt.Errorf("ssh: 用户 %q 公钥解析失败:%w", u.Name, err)
			}
			keyUsers[string(pk.Marshal())] = u.Name
		}
	}
	if len(pwUsers) == 0 && len(keyUsers) == 0 {
		return nil, errors.New("ssh: 入站需至少一个 user{password 或 public-key}")
	}
	// 认证回调把命中的【计费用户名】写进 Permissions.Extensions —— 握手后经 ctx 桥进 dispatch 计量。
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if want, ok := pwUsers[c.User()]; ok && want == string(pass) {
				return &ssh.Permissions{Extensions: map[string]string{userExt: c.User()}}, nil
			}
			return nil, errors.New("ssh: 密码认证失败")
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if name, ok := keyUsers[string(key.Marshal())]; ok {
				return &ssh.Permissions{Extensions: map[string]string{userExt: name}}, nil
			}
			return nil, errors.New("ssh: 公钥认证失败")
		},
	}
	cfg.AddHostKey(signer)
	return &Inbound{config: cfg, out: out, dispatch: dispatch}, nil
}

// HandleStream:对一条 TCP 连接做 SSH server 握手,再解复用其上的 direct-tcpip channel,
// 每条按目标路由。阻塞至该 SSH 连接结束。
func (h *Inbound) HandleStream(ctx context.Context, s link.Stream, _ *endpoint.Metadata) error {
	sconn, chans, reqs, err := ssh.NewServerConn(s, h.config)
	if err != nil {
		return err
	}
	defer sconn.Close()
	// 认证命中的计费用户名挂进 ctx(整条 SSH 连接共享),供 dispatch 计量回读;
	// 真实客户端地址(底层 TCP 的 RemoteAddr)透给每条 channel,使 max-ips 按真源计。
	if sconn.Permissions != nil {
		if name := sconn.Permissions.Extensions[userExt]; name != "" {
			ctx = withUser(ctx, name)
		}
	}
	remote := s.RemoteAddr()
	go ssh.DiscardRequests(reqs) // 丢弃全局请求(keepalive 等)
	for newCh := range chans {
		if newCh.ChannelType() != "direct-tcpip" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only direct-tcpip supported")
			continue
		}
		var p directTCPIP
		if err := ssh.Unmarshal(newCh.ExtraData(), &p); err != nil {
			_ = newCh.Reject(ssh.ConnectionFailed, "bad direct-tcpip payload")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(chReqs)
		dst := toNTR(metadata.ParseSocksaddrHostPort(p.Host, uint16(p.Port)))
		go h.route(ctx, ch, dst, remote)
	}
	return nil
}

// HandlePacket:SSH 无原生 PacketConn 入站。
func (h *Inbound) HandlePacket(context.Context, link.PacketConn, *endpoint.Metadata) error {
	return errors.New("ssh: packet inbound not supported")
}

// route 把一条已接受的 channel 路由:反连 dispatch 优先,否则 relay 到出站。
func (h *Inbound) route(ctx context.Context, ch ssh.Channel, dst addr.Socksaddr, remote net.Addr) {
	hs := connStream{channelConn{Channel: ch, remote: remote}}
	if h.dispatch != nil { // 反连 portal:已握手流交隧道派发,不落地出站
		_ = h.dispatch(ctx, hs, dst, endpoint.NetworkTCP)
		return
	}
	up, err := h.out.DialStream(ctx, dst)
	if err != nil {
		_ = ch.Close()
		return
	}
	_ = relay.Relay(hs, up) // Relay 内部收尾两端
}

// directTCPIP 是 SSH "direct-tcpip" channel open 附带数据(RFC 4254 §7.2):目标 host:port + 源。
type directTCPIP struct {
	Host     string
	Port     uint32
	OrigHost string
	OrigPort uint32
}

// channelConn 把 ssh.Channel(io.ReadWriteCloser + CloseWrite)补足成 net.Conn:SSH channel 无
// 地址/截止时间语义,用底层 TCP 的真实 RemoteAddr(供 max-ips 按真源计)+ no-op deadline
//(SSH 自带流控,relay 不依赖 deadline)。
type channelConn struct {
	ssh.Channel
	remote net.Addr // 底层 SSH 连接的客户端地址(该连接所有 channel 共享)
}

func (channelConn) LocalAddr() net.Addr { return sshAddr{} }
func (c channelConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return sshAddr{}
}
func (channelConn) SetDeadline(time.Time) error      { return nil }
func (channelConn) SetReadDeadline(time.Time) error  { return nil }
func (channelConn) SetWriteDeadline(time.Time) error { return nil }

type sshAddr struct{}

func (sshAddr) Network() string { return "ssh" }
func (sshAddr) String() string  { return "ssh-channel" }

func toNTR(a metadata.Socksaddr) addr.Socksaddr {
	return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}
