package trusttunnel

import (
	"context"
	cryptotls "crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/outbound/anytls"
	"github.com/LOVECHEN/ntr/outbound/direct"
)

// TestSessionPluginIdentity:经插件通道(LookupSession → NewHandler / NewOutbound)建的 trusttunnel 两端互通,
// 且运行时交来的 Dispatch 在 ctx 里能经 UserFromContext 回读到【用户 tag】—— 计量回读表按 tag 记账的前提。
// 覆盖顶层 users(Fields 复合键)与口内 users(Secret)两种打包。
func TestSessionPluginIdentity(t *testing.T) {
	sp, ok := registry.LookupSession("trusttunnel")
	if !ok || sp.NewHandler == nil || sp.NewOutbound == nil {
		t.Fatal("trusttunnel 未以 Handler 形态自注册")
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()
	echoDst := addr.FromIPPort(echo.Addr().(*net.TCPAddr).AddrPort())

	seen := make(chan string, 4)
	h, err := sp.NewHandler(registry.SessionInbound{
		Users: []registry.SessionUser{
			{Tag: "alice@tt-in", Fields: map[string]string{"password": "pw-a"}},
			{Tag: "bob", Secret: "pw-b", Fields: map[string]string{"name": "bob", "password": "pw-b"}},
		},
		ServerTLS: func() (*cryptotls.Config, error) { return anytls.ServerTLSConfig("", "") },
		Out:       direct.Outbound{},
		Dispatch: func(ctx context.Context, s link.Stream, dst addr.Socksaddr, _ endpoint.Network) error {
			tag, _ := UserFromContext(ctx)
			seen <- tag
			up, err := direct.Outbound{}.DialStream(ctx, dst)
			if err != nil {
				return err
			}
			go func() { _, _ = io.Copy(up, s); _ = up.Close() }()
			_, _ = io.Copy(s, up)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvLn.Close()
	go func() {
		for {
			c, err := srvLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = h.HandleStream(context.Background(), connStreamTest{c}, &endpoint.Metadata{}) }(c)
		}
	}()

	for _, tc := range []struct{ user, pw, wantTag string }{
		{"alice@tt-in", "pw-a", "alice@tt-in"},
		{"bob", "pw-b", "bob"},
	} {
		node := &spec.Node{Kind: spec.KindMap, Map: map[string]*spec.Node{
			"server": spec.Scalar(srvLn.Addr().String()), "user": spec.Scalar(tc.user),
			"secret": spec.Scalar(tc.pw), "sni": spec.Scalar("localhost"), "insecure": spec.Scalar("true"),
		}}
		out, err := sp.NewOutbound(node)
		if err != nil {
			t.Fatal(err)
		}
		st, err := out.DialStream(context.Background(), echoDst)
		if err != nil {
			t.Fatalf("%s 拨号:%v", tc.user, err)
		}
		msg := []byte("id-" + tc.user)
		if _, err := st.Write(msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(st, buf); err != nil || string(buf) != string(msg) {
			t.Fatalf("%s echo 不符:%q %v", tc.user, buf, err)
		}
		_ = st.Close()
		if got := <-seen; got != tc.wantTag {
			t.Fatalf("Dispatch ctx 回读 tag=%q,期望 %q", got, tc.wantTag)
		}
	}
}
