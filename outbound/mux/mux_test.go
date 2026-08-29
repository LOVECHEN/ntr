package mux

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	singmux "github.com/metacubex/sing-mux"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/link"
)

// TestMuxClientSelfLoop:NTR mux 客户端(mux.Outbound)↔ sing-mux Service 服务端(echo)经真 TCP 承载。
// 验客户端桥(baseDialer→base.DialStream 拨魔术目标 + connStream)对 smux/yamux 线级自洽。
// (h2mux 需 -tags http2legacy;此处只测免 tag 的 smux/yamux,保证 `go test` 无 tag 也过。)
func TestMuxClientSelfLoop(t *testing.T) {
	for _, proto := range []string{"smux", "yamux"} {
		t.Run(proto, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			svc, err := singmux.NewService(singmux.ServiceOptions{
				NewStreamContext: func(c context.Context, _ net.Conn) context.Context { return c },
				Logger:           logger.NOP(),
				Handler:          echoHandler{},
			})
			if err != nil {
				t.Fatal(err)
			}
			// 服务端:接受承载连接,交 sing-mux Service 解复用(子流 echo)。
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = svc.NewConnection(context.Background(), c, M.Metadata{})
			}()

			// base 出站:把承载连接拨到监听器(忽略魔术目标,直连)。
			out, err := NewOutbound(baseTo{ln.Addr().String()}, Options{Protocol: proto})
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()

			ctx := context.Background()
			s, err := out.DialStream(ctx, addr.FromFqdn("echo.test", 80))
			if err != nil {
				t.Fatalf("DialStream: %v", err)
			}
			defer s.Close()
			_ = s.SetDeadline(time.Now().Add(3 * time.Second))

			msg := []byte("mux-selfloop-hello-42")
			if _, err := s.Write(msg); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(s, got); err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != string(msg) {
				t.Fatalf("echo 不符:got %q want %q", got, msg)
			}
		})
	}
}

// baseTo 是最小 endpoint.Outbound:DialStream 恒连到 addr(承载连接;忽略 mux 魔术目标)。
type baseTo struct{ addr string }

func (b baseTo) DialStream(ctx context.Context, _ addr.Socksaddr) (link.Stream, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", b.addr)
	if err != nil {
		return nil, err
	}
	return connStream{c}, nil
}

func (baseTo) DialPacket(context.Context, addr.Socksaddr) (link.PacketConn, error) {
	return nil, io.EOF
}

// echoHandler 实现 sing-mux ServiceHandler:每条 TCP 子流原样回写。
type echoHandler struct{}

func (echoHandler) NewConnection(_ context.Context, conn net.Conn, _ M.Metadata) error {
	_, err := io.Copy(conn, conn)
	return err
}
func (echoHandler) NewPacketConnection(_ context.Context, _ N.PacketConn, _ M.Metadata) error {
	return nil
}
func (echoHandler) NewError(context.Context, error) {}
