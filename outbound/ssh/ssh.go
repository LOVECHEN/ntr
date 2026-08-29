// Package ssh 把 SSH 隧道接入 NTR:客户端出站(direct-tcpip channel)+ 服务端 channel 解复用入站。
//
// ★用标准库 golang.org/x/crypto/ssh(已在 NTR 直接依赖)。SSH 是会话式协议:一条 SSH 连接
// 多路复用多条 channel,故不套 NTR 的流式栈契约,而是走 endpoint.Outbound(客户端开 channel)
// + 会话解复用 InboundHandler(服务端)。channel ≈ 子流,与 core/link.Session 语义天然对应。
// SSH 自带传输加密与密钥交换/rekey,不叠 NTR 的 tls/reality 传输。
package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

var _ endpoint.Outbound = (*Outbound)(nil)

// Options 是 SSH 出站配置(auth = 密码 或 私钥,至少其一;HostKey 可空)。
type Options struct {
	Server     string // 上游 host:port
	User       string // 登录用户(默认 root)
	Password   string // 密码认证(与 PrivateKey 至少其一)
	PrivateKey string // PEM 私钥(与 Password 至少其一)
	HostKey    string // 可选:固定服务端 host key(authorized_keys 单行);空 = 不校验(仅测试环境)
}

// Outbound 是 SSH 出站:惰性建一条到上游的 SSH 连接,DialStream 在其上开 direct-tcpip channel;
// 连接断开时下次 DialStream 自动重建。
type Outbound struct {
	server string
	config *ssh.ClientConfig
	mu     sync.Mutex
	client *ssh.Client
}

// NewOutbound 构造 SSH 出站。
func NewOutbound(o Options) (*Outbound, error) {
	if o.Server == "" {
		return nil, errors.New("ssh: server 为空")
	}
	if o.User == "" {
		o.User = "root"
	}
	var auth []ssh.AuthMethod
	if o.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(o.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("ssh: 解析私钥失败:%w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if o.Password != "" {
		auth = append(auth, ssh.Password(o.Password))
	}
	if len(auth) == 0 {
		return nil, errors.New("ssh: 需 password 或 private-key 之一")
	}
	hkCallback := ssh.InsecureIgnoreHostKey() // MVP:默认不校验;配 host-key 则固定校验
	if o.HostKey != "" {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(o.HostKey))
		if err != nil {
			return nil, fmt.Errorf("ssh: 解析 host-key 失败:%w", err)
		}
		hkCallback = ssh.FixedHostKey(pk)
	}
	return &Outbound{
		server: o.Server,
		config: &ssh.ClientConfig{
			User:            o.User,
			Auth:            auth,
			HostKeyCallback: hkCallback,
			Timeout:         10 * time.Second,
		},
	}, nil
}

// DialStream 在 SSH 连接上开一条到 dst 的 direct-tcpip channel。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	cli, err := o.getClient(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := cli.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		o.reset(cli) // 连接可能已死,清掉重建一次
		cli, err = o.getClient(ctx)
		if err != nil {
			return nil, err
		}
		conn, err = cli.DialContext(ctx, "tcp", dst.String())
		if err != nil {
			return nil, err
		}
	}
	return connStream{conn}, nil
}

// DialPacket:SSH direct-tcpip 仅 TCP,无原生 UDP。
func (o *Outbound) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, errors.New("ssh: UDP not supported (direct-tcpip is TCP-only)")
}

// getClient 返回复用的 SSH 客户端,首次或重置后惰性建连。
func (o *Outbound) getClient(ctx context.Context) (*ssh.Client, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.client != nil {
		return o.client, nil
	}
	d := net.Dialer{Timeout: o.config.Timeout}
	raw, err := d.DialContext(ctx, "tcp", o.server)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(raw, o.server, o.config)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	o.client = ssh.NewClient(c, chans, reqs)
	return o.client, nil
}

// reset 关掉并清除一条已死的客户端(仅当它仍是当前客户端,避免误清刚重建的)。
func (o *Outbound) reset(dead *ssh.Client) {
	o.mu.Lock()
	if o.client == dead {
		_ = o.client.Close()
		o.client = nil
	}
	o.mu.Unlock()
}

// connStream 把 net.Conn 抬成 link.Stream。
type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }
