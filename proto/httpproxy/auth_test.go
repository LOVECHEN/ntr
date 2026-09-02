package httpproxy

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
)

type mapAuth map[string]cred.Ref

func (m mapAuth) Auth(scheme string, key []byte) (cred.Ref, bool) {
	r, ok := m[scheme+"|"+string(key)]
	return r, ok
}

// handshakePair 在 net.Pipe 上跑 客户端 CONNECT(带/不带 Basic) ↔ 服务端 ServerHandshake(authRequired 可选),
// 返回服务端解出的归属与两端错误。
func handshakePair(t *testing.T, key []byte, required bool, auth mapAuth) (cred.Ref, error, error) {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	ctx := context.Background()

	type srvOut struct {
		ref cred.Ref
		err error
	}
	so := make(chan srvOut, 1)
	go func() {
		p := &Proxy{}
		p.SetAuthRequired(required)
		_, req, err := p.ServerHandshake(ctx, pipeStream{s}, auth)
		if err != nil {
			so <- srvOut{err: err}
			return
		}
		so <- srvOut{ref: req.Cred}
	}()
	_, cerr := (&Proxy{}).ClientHandshake(ctx, pipeStream{c}, key, addr.FromFqdn("target.example", 443))
	o := <-so
	return o.ref, cerr, o.err
}

// TestBasicAuth_RequiredHit:配了 users + 客户端带正确 Basic → 归属该用户,双向成功。
func TestBasicAuth_RequiredHit(t *testing.T) {
	alice := cred.Ref{ID: cred.UserBase + 3}
	ref, cerr, serr := handshakePair(t, []byte("alice:pw"), true, mapAuth{"http|alice:pw": alice})
	if cerr != nil || serr != nil {
		t.Fatalf("应双向成功: client=%v server=%v", cerr, serr)
	}
	if ref.ID != alice.ID {
		t.Fatalf("归属应为 alice(%d),实为 %d", alice.ID, ref.ID)
	}
}

// TestBasicAuth_RequiredMissing:配了 users 但客户端不带凭据 → 服务端回 407 拒,客户端看到 407。
func TestBasicAuth_RequiredMissing(t *testing.T) {
	_, cerr, serr := handshakePair(t, nil, true, mapAuth{"http|alice:pw": {ID: cred.UserBase + 3}})
	if serr == nil {
		t.Fatal("服务端应拒(407)")
	}
	if cerr == nil || !strings.Contains(cerr.Error(), "407") {
		t.Fatalf("客户端应收到 407: %v", cerr)
	}
}

// TestBasicAuth_NotRequired:没配 users → 不带凭据也通,归属 Ambient;带了但没人登记也不拒(no-auth 语义)。
func TestBasicAuth_NotRequired(t *testing.T) {
	ref, cerr, serr := handshakePair(t, nil, false, mapAuth{})
	if cerr != nil || serr != nil {
		t.Fatalf("no-auth 应双向成功: client=%v server=%v", cerr, serr)
	}
	if ref.ID != cred.Ambient {
		t.Fatalf("no-auth 归属应为 Ambient,实为 %d", ref.ID)
	}
}
