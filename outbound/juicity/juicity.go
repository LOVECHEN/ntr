package juicity

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

// maxStreamsPerConn:规范要求 —— 若 QUIC 库不暴露对端可用流数,客户端在同一连接上累计开满 30 条
// 流后须换新连接承接后续开流(服务端 maxOpenIncomingStreams 必 ≥ 30,故永不阻塞在流额度上)。
const maxStreamsPerConn = 30

const (
	dialTimeout = 10 * time.Second
	idleTimeout = 30 * time.Second
	keepAlive   = 10 * time.Second
)

var _ endpoint.Outbound = (*Outbound)(nil)

// Options 是 Juicity 出站配置(鉴权 = UUID + Password)。
type Options struct {
	Server            string // host:port
	UUID              string
	Password          string
	SNI               string   // 空 = 取 Server 的主机名
	Insecure          bool     // 跳过证书校验
	ALPN              []string // 空 = ["h3"](规范 MUST)
	CongestionControl string   // "bbr"(默认)/ "cubic"
}

// Outbound 是 Juicity 出站:一条 QUIC 连接承载多条代理流,按规范轮换连接。
type Outbound struct {
	server   string
	uuid     [16]byte
	password string
	cc       string
	tlsConf  *tls.Config
	quicConf *quic.Config

	mu  sync.Mutex
	cur *session
}

// session 是一条已鉴权(鉴权与代理流并发发出,不等应答)的 QUIC 连接 + 开流计数。
type session struct {
	conn    *quic.Conn
	opened  int  // 累计开流数(达 maxStreamsPerConn 即退役)
	active  int  // 当前活跃流数
	retired bool // 不再接新流;活跃流归零即关
}

// NewOutbound 构造 Juicity 出站。
func NewOutbound(o Options) (*Outbound, error) {
	if o.Server == "" {
		return nil, errors.New("juicity: server 必填")
	}
	host, _, err := net.SplitHostPort(o.Server)
	if err != nil {
		return nil, fmt.Errorf("juicity: server %q: %w", o.Server, err)
	}
	uuid, err := parseUUID(o.UUID)
	if err != nil {
		return nil, err
	}
	sni := o.SNI
	if sni == "" {
		sni = host
	}
	alpn := o.ALPN
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	return &Outbound{
		server:   o.Server,
		uuid:     uuid,
		password: o.Password,
		cc:       o.CongestionControl,
		tlsConf: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: o.Insecure,
			NextProtos:         alpn,
			MinVersion:         tls.VersionTLS13,
		},
		quicConf: &quic.Config{
			MaxIdleTimeout:  idleTimeout,
			KeepAlivePeriod: keepAlive,
		},
	}, nil
}

// DialStream 开一条 TCP 代理流:流首 [0x01][目标] 立即单独发出(规范允许流首与数据分开发;
// 先发流首可免「服务端先说话」的协议卡在等客户端首包上)。
func (o *Outbound) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	return o.openProxyStream(ctx, networkTCP, dst)
}

// DialPacket 开一条 UDP 代理流:流首 [0x03][目标],之后按帧收发(可多目标)。
func (o *Outbound) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	sc, err := o.openProxyStream(ctx, networkUDP, dst)
	if err != nil {
		return nil, err
	}
	return &packetConn{s: sc}, nil
}

func (o *Outbound) openProxyStream(ctx context.Context, network byte, dst addr.Socksaddr) (*streamConn, error) {
	hdr, err := appendStreamHeader(nil, network, dst)
	if err != nil {
		return nil, err
	}
	s, err := o.acquire(ctx)
	if err != nil {
		return nil, err
	}
	st, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		o.release(s)
		return nil, fmt.Errorf("juicity: 开流: %w", err)
	}
	sc := newStreamConn(st, s.conn, func() { o.release(s) })
	if _, err := sc.Write(hdr); err != nil {
		_ = sc.Close()
		return nil, fmt.Errorf("juicity: 写流首: %w", err)
	}
	return sc, nil
}

// acquire 取一条可接新流的会话(必要时轮换/新建),并占一个流额度。
func (o *Outbound) acquire(ctx context.Context) (*session, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := o.cur
	if s == nil || s.opened >= maxStreamsPerConn || s.conn.Context().Err() != nil {
		if s != nil {
			o.retireLocked(s)
		}
		ns, err := o.dial(ctx)
		if err != nil {
			return nil, err
		}
		o.cur, s = ns, ns
	}
	s.opened++
	s.active++
	return s, nil
}

func (o *Outbound) release(s *session) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s.active--
	if s.retired && s.active <= 0 {
		_ = s.conn.CloseWithError(0, "")
	}
}

func (o *Outbound) retireLocked(s *session) {
	s.retired = true
	if o.cur == s {
		o.cur = nil
	}
	if s.active <= 0 {
		_ = s.conn.CloseWithError(0, "")
	}
}

// dial 建新 QUIC 连接并在单向流上发鉴权(不等应答;服务端鉴权通过后才处理代理流)。
func (o *Outbound) dial(ctx context.Context) (*session, error) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := quic.DialAddr(dctx, o.server, o.tlsConf, o.quicConf)
	if err != nil {
		return nil, fmt.Errorf("juicity: 拨 %s: %w", o.server, err)
	}
	setCongestion(conn, o.cc)
	tok, err := genToken(conn.ConnectionState().TLS, o.uuid, o.password)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, fmt.Errorf("juicity: 导出 token: %w", err)
	}
	uni, err := conn.OpenUniStream()
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, fmt.Errorf("juicity: 开鉴权流: %w", err)
	}
	if _, err := uni.Write(appendAuth(nil, o.uuid, tok)); err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, fmt.Errorf("juicity: 写鉴权: %w", err)
	}
	_ = uni.Close()
	return &session{conn: conn}, nil
}

// Close 关闭当前会话(活跃流随连接关闭而结束)。
func (o *Outbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cur != nil {
		_ = o.cur.conn.CloseWithError(0, "")
		o.cur = nil
	}
	return nil
}

// parseUUID 解析标准 UUID 文本(带或不带连字符)为 16 字节。
func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	h := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(h) != 32 {
		return u, fmt.Errorf("juicity: uuid %q 长度不对", s)
	}
	if _, err := hex.Decode(u[:], []byte(h)); err != nil {
		return u, fmt.Errorf("juicity: uuid %q: %w", s, err)
	}
	return u, nil
}
