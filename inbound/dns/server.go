// Package dnsin 是 DNS 服务端入站:监听 UDP+TCP,把查询交给内置 route.Resolver(fake-ip/hosts/缓存/上游
// 全在其中)就地应答。用于把本机 DNS 指向 NTR —— 配合 fake-ip 让「只见 IP」的连接也能按域名分流,
// 且这些域名的解析不经系统 DNS 外泄(上游 detour 强制具名)。对齐 sing-box/mihomo 的 dns server 入站。
package dnsin

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/LOVECHEN/ntr/core/route"
)

// Server 监听 UDP+TCP DNS,查询交 resolver.Exchange。
type Server struct{ r route.Resolver }

// New 建 DNS 入站(resolver 必给)。
func New(r route.Resolver) *Server { return &Server{r: r} }

// Run 绑 listen 的 UDP + TCP,阻塞至 ctx 取消。
func (s *Server) Run(ctx context.Context, listen string) error {
	uc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", listen)
	if err != nil {
		_ = uc.Close()
		return err
	}
	go func() { <-ctx.Done(); _ = uc.Close(); _ = l.Close() }()
	go s.serveUDP(ctx, uc)
	return s.serveTCP(ctx, l)
}

func (s *Server) serveUDP(ctx context.Context, uc net.PacketConn) {
	buf := make([]byte, 4096) // DNS UDP 报文上界(EDNS0 常配 4096);同步拷贝后再并发处理
	for {
		n, from, err := uc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		go func() {
			resp, err := s.r.Exchange(ctx, &route.Message{Raw: q})
			if err != nil || resp == nil {
				return
			}
			_, _ = uc.WriteTo(resp.Raw, from)
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context, l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return nil // ctx 取消关闭 listener → Accept 出错即正常收尾
		}
		go s.handleTCP(ctx, c)
	}
}

// handleTCP 处理 DNS-over-TCP:每报文前置 2 字节大端长度(RFC 1035 §4.2.2)。
func (s *Server) handleTCP(ctx context.Context, c net.Conn) {
	defer c.Close()
	for {
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp, err := s.r.Exchange(ctx, &route.Message{Raw: q})
		if err != nil || resp == nil {
			return
		}
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(resp.Raw)))
		if _, err := c.Write(append(out[:], resp.Raw...)); err != nil {
			return
		}
	}
}
