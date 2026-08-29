package tlsmirror

import (
	"context"
	"net"
	"strings"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
)

var _ transport.BaseTransport = (*Transport)(nil)

// Config 是 NTR tlsmirror 层配置。primary-key 两端共享(base64 32B);sni 是载体真 TLS 的 SNI(=被镜像
// 真后端域名),客户端用;dest 是真后端 host:port,服务端逐连接拨号并镜像;insecure 客户端跳过后端证书校验。
type Config struct {
	PrimaryKey    string
	SNI           string
	Dest          string // 服务端:被镜像的真后端 host:port(如 www.microsoft.com:443)
	Insecure      bool
	ALPN          []string
	Padding       bool // 传输层填充(可选抗检测层,两端须一致)
	Watermark     bool // 序列水印(可选抗检测层,两端须一致)
	ExplicitNonce bool // TLS1.2 显式 nonce 载体(客户端钉 TLS1.2+GCM;两端识别推荐套件)
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	sni := n.Get("sni").Str()
	if sni == "" {
		sni = n.Get("server-name").Str()
	}
	dest := n.Get("dest").Str()
	if dest == "" {
		dest = n.Get("forward").Str()
	}
	var alpn []string
	if s := n.Get("alpn").Str(); s != "" {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				alpn = append(alpn, p)
			}
		}
	}
	return Config{
		PrimaryKey:    n.Get("primary-key").Str(),
		SNI:           sni,
		Dest:          dest,
		Insecure:      n.Get("insecure").Bool(),
		ALPN:          alpn,
		Padding:       n.Get("padding").Bool(),
		Watermark:     n.Get("watermark").Bool(),
		ExplicitNonce: n.Get("explicit-nonce").Bool(),
	}, nil
}

// explicitSuites 返回启用显式 nonce 时的推荐识别套件列表(否则 nil → 恒 TLS1.3 路径)。
func (c Config) explicitSuites() []uint16 {
	if c.ExplicitNonce {
		return RecommendedExplicitNonceCipherSuites
	}
	return nil
}

// Transport 是 tlsmirror 传输句柄。
type Transport struct{ cfg Config }

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	return &Transport{cfg: cfg}, nil
}

// DialBase:拨到 tlsmirror 服务端(server)→ 建隐蔽隧道 → 可靠 link.Stream。
func (t *Transport) DialBase(ctx context.Context, server string) (link.Stream, error) {
	raw, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	sni := t.cfg.SNI
	if sni == "" {
		if h, _, e := net.SplitHostPort(server); e == nil {
			sni = h
		}
	}
	hidden, err := Dial(ctx, raw, ClientConfig{
		PrimaryKey:                t.cfg.PrimaryKey,
		ServerName:                sni,
		SkipCertVerify:            t.cfg.Insecure,
		ALPN:                      t.cfg.ALPN,
		Padding:                   t.cfg.Padding,
		Watermark:                 t.cfg.Watermark,
		ExplicitNonceCipherSuites: t.cfg.explicitSuites(),
		CarrierTLS12:              t.cfg.ExplicitNonce,
	})
	if err != nil {
		return nil, err
	}
	return connStream{hidden}, nil
}

// ListenBase:TCP 监听载体连接;每条起 goroutine 拨真后端 + 透明镜像,激活的隐蔽连接送进 Accept 队列。
func (t *Transport) ListenBase(_ context.Context, listen string) (transport.BaseListener, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	lctx, cancel := context.WithCancel(context.Background())
	ml := &mirrorListener{ln: ln, cfg: t.cfg, ctx: lctx, cancel: cancel, accepted: make(chan acceptResult, 16)}
	go ml.acceptLoop()
	return ml, nil
}

type acceptResult struct {
	s   link.Stream
	err error
}

// mirrorListener 把"TCP 监听 + 逐连接镜像激活"抬成 transport.BaseListener。
type mirrorListener struct {
	ln       net.Listener
	cfg      Config
	ctx      context.Context
	cancel   context.CancelFunc
	accepted chan acceptResult
}

func (m *mirrorListener) acceptLoop() {
	for {
		carrier, err := m.ln.Accept()
		if err != nil {
			select {
			case m.accepted <- acceptResult{err: err}:
			case <-m.ctx.Done():
			}
			return
		}
		go m.serveCarrier(carrier)
	}
}

func (m *mirrorListener) serveCarrier(carrier net.Conn) {
	forward, err := net.Dial("tcp", m.cfg.Dest)
	if err != nil {
		_ = carrier.Close()
		return
	}
	hidden, err := ServeConnReady(m.ctx, carrier, forward, ServerConfig{PrimaryKey: m.cfg.PrimaryKey, Padding: m.cfg.Padding, Watermark: m.cfg.Watermark, ExplicitNonceCipherSuites: m.cfg.explicitSuites()})
	if err != nil {
		// 探测/非隧道连接:已被透明镜像到真后端(诱骗),静默收尾。
		return
	}
	select {
	case m.accepted <- acceptResult{s: connStream{hidden}}:
	case <-m.ctx.Done():
		_ = hidden.Close()
	}
}

func (m *mirrorListener) Accept() (link.Stream, error) {
	select {
	case r := <-m.accepted:
		return r.s, r.err
	case <-m.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (m *mirrorListener) Close() error {
	m.cancel()
	return m.ln.Close()
}

func (m *mirrorListener) Addr() net.Addr { return m.ln.Addr() }

// connStream 把隐蔽 net.Conn 抬成 link.Stream。
type connStream struct{ net.Conn }

func (connStream) Unwrap() any { return nil }

var _ link.Stream = connStream{}

// 注册 tlsmirror 传输层(Band=Base,居栈底 —— 镜像真 TLS 会话产隐蔽可靠流)。manifest blank-import 链入。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "tlsmirror",
		Display: "tlsmirror (covert TLS record mirror)",
		Band:    registry.BandBase,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
