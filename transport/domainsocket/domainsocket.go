// Package domainsocket 是 Unix 域套接字基础传输(对齐 v2ray 的 DomainSocket):用 unix socket 替代 TCP 作
// 栈底可靠流,其上照常叠 tls / 终端协议 —— 同机多进程(如前置 nginx / haproxy 经 unix socket 转进来)免占端口。
// 线上就是裸字节流,无额外帧。
//
// 配置块 domainsocket::path(套接字路径;缺省取入站 listen / 出站 server)、abstract(Linux 抽象命名空间,
// 不落文件)、padding(抽象名补零到 sun_path 全长 108 字节,与 HAProxy 等按全长寻址的实现互通;仅 abstract 时有意义)。
package domainsocket

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
)

// sunPathLen 是 struct sockaddr_un 的 sun_path 长度(Linux)。
const sunPathLen = 108

// Config 是 domainsocket 块。
type Config struct {
	Path     string
	Abstract bool
	Padding  bool
}

// Parse 从哑节点解出 Config(path 可空:运行期回落 listen / server)。
func Parse(n *spec.Node) (Config, error) {
	return Config{Path: n.Get("path").Str(), Abstract: n.Get("abstract").Bool(), Padding: n.Get("padding").Bool()}, nil
}

// Build 建传输句柄。
func Build(_ context.Context, cfg Config, _ any) (any, error) { return &Transport{cfg: cfg}, nil }

// Transport 实现 transport.BaseTransport。
type Transport struct{ cfg Config }

var _ transport.BaseTransport = (*Transport)(nil)

// sockName 解出 unix 地址名:配置 path 优先,否则用 fallback(listen / server);abstract 加前导 '@'
// (Go 把它映射成 sun_path 首字节 0),padding 再补零到全长。
func (t *Transport) sockName(fallback string) (string, error) {
	p := t.cfg.Path
	if p == "" {
		p = fallback
	}
	if p == "" {
		return "", errors.New("domainsocket: 需要 path(或在 listen / server 写套接字路径)")
	}
	if !t.cfg.Abstract {
		return p, nil
	}
	if !strings.HasPrefix(p, "@") {
		p = "@" + p
	}
	if t.cfg.Padding && len(p) < sunPathLen {
		p += strings.Repeat("\x00", sunPathLen-len(p))
	}
	return p, nil
}

// DialBase 拨 unix 套接字(server 仅在未配 path 时作路径)。
func (t *Transport) DialBase(ctx context.Context, server string) (link.Stream, error) {
	name, err := t.sockName(server)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", name)
	if err != nil {
		return nil, err
	}
	return connStream{c}, nil
}

// ListenBase 监听 unix 套接字(listen 仅在未配 path 时作路径)。文件型套接字:清掉残留的旧套接字文件,
// 关闭时自动删除;抽象命名空间不落文件。
func (t *Transport) ListenBase(_ context.Context, listen string) (transport.BaseListener, error) {
	name, err := t.sockName(listen)
	if err != nil {
		return nil, err
	}
	if !t.cfg.Abstract {
		if fi, err := os.Lstat(name); err == nil && fi.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(name)
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(!t.cfg.Abstract)
	return listener{ln}, nil
}

type listener struct{ *net.UnixListener }

func (l listener) Accept() (link.Stream, error) {
	c, err := l.UnixListener.Accept()
	if err != nil {
		return nil, err
	}
	return connStream{c}, nil
}

type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }
