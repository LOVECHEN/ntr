package kcptun

import (
	"context"
	"net"
	"sync"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
)

var _ transport.BaseTransport = (*Transport)(nil)

// Parse 从哑节点解出 Config(字段名对齐 mihomo kcptun-opts / xtaci-kcptun)。
func Parse(n *spec.Node) (Config, error) {
	return Config{
		Key:          n.Get("key").Str(),
		Crypt:        n.Get("crypt").Str(),
		Mode:         n.Get("mode").Str(),
		Conn:         n.Get("conn").Int(0),
		MTU:          n.Get("mtu").Int(0),
		RateLimit:    n.Get("ratelimit").Int(0),
		SndWnd:       n.Get("sndwnd").Int(0),
		RcvWnd:       n.Get("rcvwnd").Int(0),
		DataShard:    n.Get("datashard").Int(0),
		ParityShard:  n.Get("parityshard").Int(0),
		DSCP:         n.Get("dscp").Int(0),
		NoComp:       n.Get("nocomp").Bool(),
		AckNodelay:   n.Get("acknodelay").Bool(),
		NoDelay:      n.Get("nodelay").Int(0),
		Interval:     n.Get("interval").Int(0),
		Resend:       n.Get("resend").Int(0),
		NoCongestion: n.Get("nc").Int(0),
		SockBuf:      n.Get("sockbuf").Int(0),
		SmuxVer:      n.Get("smuxver").Int(0),
		SmuxBuf:      n.Get("smuxbuf").Int(0),
		FrameSize:    n.Get("framesize").Int(0),
		StreamBuf:    n.Get("streambuf").Int(0),
		KeepAlive:    n.Get("keepalive").Int(0),
	}, nil
}

// Transport 是 kcptun 传输句柄;客户端会话池 cli 跨 DialBase 共用。
type Transport struct {
	cfg  Config
	once sync.Once
	cli  *client
}

// Build 构造 Transport(补齐默认值)。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	cfg.FillDefaults()
	return &Transport{cfg: cfg}, nil
}

func (t *Transport) client() *client {
	t.once.Do(func() { t.cli = newClient(t.cfg) })
	return t.cli
}

// DialBase:向 server(UDP)开一条 kcptun 会话流。会话按 Conn 数复用。
func (t *Transport) DialBase(ctx context.Context, server string) (link.Stream, error) {
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	dial := func(_ context.Context) (net.PacketConn, net.Addr, error) {
		pc, err := net.ListenUDP("udp", nil) // 临时本地端口;kcp 拥有并负责关闭
		if err != nil {
			return nil, nil, err
		}
		return pc, raddr, nil
	}
	st, err := t.client().openStream(ctx, dial)
	if err != nil {
		return nil, err
	}
	return connStream{st}, nil
}

// ListenBase:UDP 监听 → kcptun 服务端接受 smux 流,每流送进 Accept 队列。
func (t *Transport) ListenBase(_ context.Context, listen string) (transport.BaseListener, error) {
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return nil, err
	}
	l := &kcptunListener{pc: pc, accepted: make(chan link.Stream, 64), done: make(chan struct{})}
	srv := newServer(t.cfg)
	go func() {
		_ = srv.serve(pc, func(c net.Conn) {
			select {
			case l.accepted <- connStream{c}:
			case <-l.done:
				_ = c.Close()
			}
		})
		l.closeOnce.Do(func() { close(l.done) })
	}()
	return l, nil
}

// kcptunListener 把 kcptun 服务端抬成 transport.BaseListener。
type kcptunListener struct {
	pc        net.PacketConn
	accepted  chan link.Stream
	done      chan struct{}
	closeOnce sync.Once
}

func (l *kcptunListener) Accept() (link.Stream, error) {
	select {
	case s := <-l.accepted:
		return s, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *kcptunListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.pc.Close()
}

func (l *kcptunListener) Addr() net.Addr { return l.pc.LocalAddr() }

// connStream 把 smux 流(net.Conn)抬成 link.Stream。
type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

var _ link.Stream = connStream{}

// 注册 kcptun 传输层(Band=Base,居栈底 —— UDP+KCP+FEC+smux 可靠隧道)。manifest blank-import 链入。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "kcptun",
		Display: "kcptun (KCP+FEC+smux tunnel)",
		Band:    registry.BandBase,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
