package service

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// blockingServer 是一个在 ServerHandshake 里【阻塞读】的 stub proxy.Server:模拟「客户端先说话」协议
// 遇到连上不发字节的 slow-loris —— 用来验证 reaper Seam 1 的握手 deadline 会打断它。
type blockingServer struct{ readErr chan error }

func (s *blockingServer) ServerHandshake(_ context.Context, below link.Stream, _ proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	_, err := below.Read(make([]byte, 1)) // 客户端静默 → 阻塞在此,直到握手 deadline 触发读超时
	s.readErr <- err
	return nil, nil, err
}

// TestHandshakeDeadline 守 reaper Seam 1(§10):裸流连上后一字节不发,Handshake 必须在 HandshakeTimeout
// 内因读超时返回(释放 goroutine+fd),而非永久钉住。
func TestHandshakeDeadline(t *testing.T) {
	srv := &blockingServer{readErr: make(chan error, 1)}
	h := &ProxyInbound{
		Proxy:            srv,
		Out:              StaticOutbound{Out: nil},
		HandshakeTimeout: 150 * time.Millisecond,
	}
	cP, c := net.Pipe()
	defer cP.Close()

	done := make(chan error, 1)
	go func() {
		done <- h.HandleStream(context.Background(), connStream{c}, &endpoint.Metadata{Network: endpoint.NetworkTCP})
	}()

	// 客户端全程静默(不写 cP)。断言握手在 deadline 内因超时返回。
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("slow-loris 握手应超时报错,却成功返回")
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Logf("返回错误(非 deadline 类也可接受,只要非永久阻塞):%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("握手 deadline 未生效:HandleStream 在超时后仍未返回(slow-loris 钉住 goroutine)")
	}
	// stub 的阻塞读也应已被 deadline 解开。
	select {
	case <-srv.readErr:
	case <-time.After(time.Second):
		t.Fatal("ServerHandshake 的阻塞读未被 deadline 打断")
	}
}
