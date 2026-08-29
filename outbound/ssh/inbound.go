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
	pwUsers := map[string]string{} // name → password
	keyUsers := map[string]bool{}  // marshaled authorized key → allowed
	for _, u := range users {
		if u.Password != "" {
			pwUsers[u.Name] = u.Password
		}
		if u.PublicKey != "" {
			pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(u.PublicKey))
			if err != nil {
				return nil, fmt.Errorf("ssh: 用户 %q 公钥解析失败:%w", u.Name, err)
			}
			keyUsers[string(pk.Marshal())] = true
		}
	}
	if len(pwUsers) == 0 && len(keyUsers) == 0 {
		return nil, errors.New("ssh: 入站需至少一个 user{password 或 public-key}")
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if want, ok := pwUsers[c.User()]; ok && want == string(pass) {
				return nil, nil
			}
			return nil, errors.New("ssh: 密码认证失败")
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if keyUsers[string(key.Marshal())] {
				return nil, nil
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
		go h.route(ctx, ch, dst)
	}
	return nil
}

// HandlePacket:SSH 无原生 PacketConn 入站。
func (h *Inbound) HandlePacket(context.Context, link.PacketConn, *endpoint.Metadata) error {
	return errors.New("ssh: packet inbound not supported")
}

// route 把一条已接受的 channel 路由:反连 dispatch 优先,否则 relay 到出站。
func (h *Inbound) route(ctx context.Context, ch ssh.Channel, dst addr.Socksaddr) {
	hs := connStream{channelConn{Channel: ch}}
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
// 地址/截止时间语义,用假地址 + no-op deadline(SSH 自带流控,relay 不依赖 deadline)。
type channelConn struct {
	ssh.Channel
}

func (channelConn) LocalAddr() net.Addr              { return sshAddr{} }
func (channelConn) RemoteAddr() net.Addr             { return sshAddr{} }
func (channelConn) SetDeadline(time.Time) error      { return nil }
func (channelConn) SetReadDeadline(time.Time) error  { return nil }
func (channelConn) SetWriteDeadline(time.Time) error { return nil }

type sshAddr struct{}

func (sshAddr) Network() string { return "ssh" }
func (sshAddr) String() string  { return "ssh-channel" }

func toNTR(a metadata.Socksaddr) addr.Socksaddr {
	return addr.Socksaddr{Addr: a.Addr, Port: a.Port, Fqdn: a.Fqdn}
}
