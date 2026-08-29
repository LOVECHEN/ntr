package kcptun

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/metacubex/kcp-go"
	"github.com/metacubex/randv2"
	"github.com/metacubex/smux"
)

// dialFn 拨底层 UDP:返回 PacketConn + 服务端地址(kcp.NewConn4 用)。
type dialFn func(ctx context.Context) (net.PacketConn, net.Addr, error)

// client 是 kcptun 客户端:维护 Conn 条 smux 会话(KCP over UDP),轮询开流。承 mihomo/xtaci-kcptun。
type client struct {
	config Config
	block  kcp.BlockCrypt

	once    sync.Once
	numconn uint16
	muxes   []*smux.Session
	rr      uint16
	mu      sync.Mutex
}

func newClient(config Config) *client {
	config.FillDefaults()
	return &client{config: config, block: config.NewBlock()}
}

// createConn 建一条会话:UDP → KCP(convid 随机,FEC,加密)→ 可选 snappy → smux.Client。
func (c *client) createConn(ctx context.Context, dial dialFn) (*smux.Session, error) {
	conn, addr, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	cfg := c.config
	convid := randv2.Uint32()
	kcpconn, err := kcp.NewConn4(convid, addr, c.block, cfg.DataShard, cfg.ParityShard, true, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	kcpconn.SetStreamMode(true)
	kcpconn.SetWriteDelay(false)
	kcpconn.SetNoDelay(cfg.NoDelay, cfg.Interval, cfg.Resend, cfg.NoCongestion)
	kcpconn.SetWindowSize(cfg.SndWnd, cfg.RcvWnd)
	kcpconn.SetMtu(cfg.MTU)
	kcpconn.SetACKNoDelay(cfg.AckNodelay)
	kcpconn.SetRateLimit(uint32(cfg.RateLimit))
	_ = kcpconn.SetDSCP(cfg.DSCP)
	_ = kcpconn.SetReadBuffer(cfg.SockBuf)
	_ = kcpconn.SetWriteBuffer(cfg.SockBuf)

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = cfg.SmuxVer
	smuxConfig.MaxReceiveBuffer = cfg.SmuxBuf
	smuxConfig.MaxStreamBuffer = cfg.StreamBuf
	smuxConfig.MaxFrameSize = cfg.FrameSize
	smuxConfig.KeepAliveInterval = time.Duration(cfg.KeepAlive) * time.Second
	if smuxConfig.KeepAliveInterval >= smuxConfig.KeepAliveTimeout {
		smuxConfig.KeepAliveTimeout = 3 * smuxConfig.KeepAliveInterval
	}
	if err := smux.VerifyConfig(smuxConfig); err != nil {
		_ = kcpconn.Close()
		return nil, err
	}
	var netConn net.Conn = kcpconn
	if !cfg.NoComp {
		netConn = newCompStream(netConn)
	}
	return smux.Client(netConn, smuxConfig)
}

// openStream 轮询挑一条会话(死则重建),开一条 smux 流。
func (c *client) openStream(ctx context.Context, dial dialFn) (*smux.Stream, error) {
	c.once.Do(func() {
		c.numconn = uint16(c.config.Conn)
		c.muxes = make([]*smux.Session, c.config.Conn)
	})
	c.mu.Lock()
	idx := c.rr % c.numconn
	if c.muxes[idx] == nil || c.muxes[idx].IsClosed() {
		sess, err := c.createConn(ctx, dial)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		c.muxes[idx] = sess
	}
	c.rr++
	sess := c.muxes[idx]
	c.mu.Unlock()
	return sess.OpenStream()
}

// server 是 kcptun 服务端:KCP 接受 → 每 KCP 会话起 smux.Server → 每流交 handler。
type server struct {
	config Config
	block  kcp.BlockCrypt
}

func newServer(config Config) *server {
	config.FillDefaults()
	return &server{config: config, block: config.NewBlock()}
}

// serve 在 pc 上跑 kcptun 服务端,每条 smux 流回调 handler。阻塞直到 pc 出错/关闭。
func (s *server) serve(pc net.PacketConn, handler func(net.Conn)) error {
	lis, err := kcp.ServeConn(s.block, s.config.DataShard, s.config.ParityShard, pc)
	if err != nil {
		return err
	}
	defer lis.Close()
	_ = lis.SetDSCP(s.config.DSCP)
	_ = lis.SetReadBuffer(s.config.SockBuf)
	_ = lis.SetWriteBuffer(s.config.SockBuf)
	for {
		conn, err := lis.AcceptKCP()
		if err != nil {
			return err
		}
		conn.SetStreamMode(true)
		conn.SetWriteDelay(false)
		conn.SetNoDelay(s.config.NoDelay, s.config.Interval, s.config.Resend, s.config.NoCongestion)
		conn.SetMtu(s.config.MTU)
		conn.SetWindowSize(s.config.SndWnd, s.config.RcvWnd)
		conn.SetACKNoDelay(s.config.AckNodelay)
		conn.SetRateLimit(uint32(s.config.RateLimit))
		var netConn net.Conn = conn
		if !s.config.NoComp {
			netConn = newCompStream(netConn)
		}
		go func() {
			smuxConfig := smux.DefaultConfig()
			smuxConfig.Version = s.config.SmuxVer
			smuxConfig.MaxReceiveBuffer = s.config.SmuxBuf
			smuxConfig.MaxStreamBuffer = s.config.StreamBuf
			smuxConfig.MaxFrameSize = s.config.FrameSize
			smuxConfig.KeepAliveInterval = time.Duration(s.config.KeepAlive) * time.Second
			if smuxConfig.KeepAliveInterval >= smuxConfig.KeepAliveTimeout {
				smuxConfig.KeepAliveTimeout = 3 * smuxConfig.KeepAliveInterval
			}
			mux, err := smux.Server(netConn, smuxConfig)
			if err != nil {
				return
			}
			defer mux.Close()
			for {
				stream, err := mux.AcceptStream()
				if err != nil {
					return
				}
				go handler(stream)
			}
		}()
	}
}
