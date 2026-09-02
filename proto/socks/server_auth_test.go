package socks

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
)

// mapAuth 是测试用 Authenticator:(scheme, key) 精确表。
type mapAuth map[string]cred.Ref

func (m mapAuth) Auth(scheme string, key []byte) (cred.Ref, bool) {
	r, ok := m[scheme+"|"+string(key)]
	return r, ok
}

// runServer 起真 TCP 监听,accept 一条连接跑 ServerHandshake,把结果送回通道。
func runServer(t *testing.T, p *Proxy, auth mapAuth) (string, chan error, chan cred.Ref) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	errs := make(chan error, 1)
	refs := make(chan cred.Ref, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errs <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, req, err := p.ServerHandshake(context.Background(), pipeStream{c}, auth)
		if err != nil {
			errs <- err
			return
		}
		refs <- req.Cred
		errs <- nil
	}()
	return ln.Addr().String(), errs, refs
}

func dialClient(t *testing.T, target string, key []byte) error {
	t.Helper()
	c, err := net.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = (&Proxy{}).ClientHandshake(context.Background(), pipeStream{c}, key, addr.FromFqdn("t.com", 80))
	return err
}

// TestServerUserPass_Required:本口配了 users(authRequired)→ 客户端 RFC1929 命中即得该用户的 cred;
// 密码错则服务端拒(子协商回 0x01)、客户端握手失败。
func TestServerUserPass_Required(t *testing.T) {
	alice := cred.Ref{ID: cred.UserBase + 7}
	auth := mapAuth{"socks|alice:secret": alice}

	srv := &Proxy{}
	srv.SetAuthRequired(true)
	target, errs, refs := runServer(t, srv, auth)
	if err := dialClient(t, target, []byte("alice:secret")); err != nil {
		t.Fatalf("正确凭据客户端握手应成功: %v", err)
	}
	if err := <-errs; err != nil {
		t.Fatalf("服务端握手应成功: %v", err)
	}
	if got := <-refs; got.ID != alice.ID {
		t.Fatalf("归属应为 alice(%d),实为 %d", alice.ID, got.ID)
	}

	srv2 := &Proxy{}
	srv2.SetAuthRequired(true)
	target2, errs2, _ := runServer(t, srv2, auth)
	if err := dialClient(t, target2, []byte("alice:wrong")); err == nil {
		t.Fatal("错误口令客户端握手应失败")
	}
	if err := <-errs2; err == nil {
		t.Fatal("服务端应拒绝错误口令")
	}
}

// TestServerNoAuth_WhenNotRequired:没配 users → 保持 no-auth,客户端不带凭据也通,归属 Ambient。
// 配了 users 但客户端只提供 no-auth → 服务端回 0xFF 拒。
func TestServerNoAuth_WhenNotRequired(t *testing.T) {
	srv := &Proxy{} // authRequired=false
	target, errs, refs := runServer(t, srv, mapAuth{})
	if err := dialClient(t, target, nil); err != nil {
		t.Fatalf("no-auth 客户端应通: %v", err)
	}
	if err := <-errs; err != nil {
		t.Fatalf("服务端 no-auth 应成功: %v", err)
	}
	if got := <-refs; got.ID != cred.Ambient {
		t.Fatalf("no-auth 归属应为 Ambient,实为 %d", got.ID)
	}

	gated := &Proxy{}
	gated.SetAuthRequired(true)
	target2, errs2, _ := runServer(t, gated, mapAuth{})
	if err := dialClient(t, target2, nil); err == nil {
		t.Fatal("配了 users 而客户端不出示凭据,应被拒")
	}
	if err := <-errs2; err == nil {
		t.Fatal("服务端应回 0xFF 拒绝仅 no-auth 的客户端")
	}
}
