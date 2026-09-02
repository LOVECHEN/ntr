package mixed

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/proto/socks"
)

// mapAuth:装配侧登记的是 (mixed, "user:pass");子插件查 socks/http 应经 aliasAuth 映回 mixed 命中。
type mapAuth map[string]cred.Ref

func (m mapAuth) Auth(scheme string, key []byte) (cred.Ref, bool) {
	r, ok := m[scheme+"|"+string(key)]
	return r, ok
}

// TestMixedAliasAuth_SocksUserPass:mixed 口配了 users(authRequired)→ socks5 客户端带 user:pass 经 RFC1929
// 命中登记在 "mixed" 下的凭据,归属该用户;错口令拒。
func TestMixedAliasAuth_SocksUserPass(t *testing.T) {
	alice := cred.Ref{ID: cred.UserBase + 9}
	auth := mapAuth{"mixed|alice:pw": alice}

	run := func(key []byte) (cred.Ref, error, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		type out struct {
			ref cred.Ref
			err error
		}
		so := make(chan out, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				so <- out{err: err}
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			v, err := Build(context.Background(), Config{}, nil)
			if err != nil {
				so <- out{err: err}
				return
			}
			p := v.(*Proxy)
			p.SetAuthRequired(true)
			_, req, err := p.ServerHandshake(context.Background(), pipeStream{c}, auth)
			if err != nil {
				so <- out{err: err}
				return
			}
			so <- out{ref: req.Cred}
		}()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, cerr := (&socks.Proxy{}).ClientHandshake(context.Background(), pipeStream{c}, key, addr.FromFqdn("t.com", 80))
		o := <-so
		return o.ref, cerr, o.err
	}

	ref, cerr, serr := run([]byte("alice:pw"))
	if cerr != nil || serr != nil {
		t.Fatalf("正确凭据应双向成功: client=%v server=%v", cerr, serr)
	}
	if ref.ID != alice.ID {
		t.Fatalf("归属应为 alice(%d),实为 %d", alice.ID, ref.ID)
	}
	if _, cerr, serr := run([]byte("alice:wrong")); cerr == nil || serr == nil {
		t.Fatal("错口令应被拒")
	}
}
