package config

import (
	"context"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/outbound/direct"
)

// 假会话式插件:捕获运行时交来的输入,验证通用插件通道(config 不认协议名)把顶层 users / 口内 users /
// 出站字段正确打包。
var (
	capturedIn  []registry.SessionInbound
	capturedOut []*spec.Node
)

type nopRunner struct{}

func (nopRunner) Run(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() }

func init() {
	registry.RegisterSession(registry.Session{
		Name: "fakesess",
		NewInbound: func(in registry.SessionInbound) (registry.Runner, error) {
			capturedIn = append(capturedIn, in)
			return nopRunner{}, nil
		},
		NewOutbound: func(n *spec.Node) (endpoint.Outbound, error) {
			capturedOut = append(capturedOut, n)
			return direct.Outbound{}, nil
		},
		UserFromContext: func(context.Context) (string, bool) { return "", false },
	})
}

func buildYAML(t *testing.T, src string) {
	t.Helper()
	var f File
	if err := yaml.Unmarshal([]byte(src), &f); err != nil {
		t.Fatalf("解析: %v", err)
	}
	if _, err := f.Build(context.Background()); err != nil {
		t.Fatalf("Build: %v", err)
	}
}

// 顶层 users(第 4 章):keys.<插件名> 复合键 → 插件收到 tag=BillID + Fields;运行时钩子齐全。
func TestSessionPluginTopLevelUsers(t *testing.T) {
	capturedIn = nil
	buildYAML(t, `
users:
  - name: alice
    keys:
      fakesess:
        uuid: 11111111-1111-1111-1111-111111111111
        password: pw-a
inbounds:
  - name: fs-in
    type: fakesess
    listen: 127.0.0.1:0
    custom-knob: on
outbounds:
  - name: direct
    type: direct
`)
	if len(capturedIn) != 1 {
		t.Fatalf("插件 NewInbound 调用 %d 次,期望 1", len(capturedIn))
	}
	in := capturedIn[0]
	if len(in.Users) != 1 {
		t.Fatalf("用户数 %d,期望 1: %+v", len(in.Users), in.Users)
	}
	u := in.Users[0]
	if u.Tag != "alice@fs-in" || u.Fields["uuid"] != "11111111-1111-1111-1111-111111111111" || u.Fields["password"] != "pw-a" {
		t.Fatalf("顶层用户打包错: %+v", u)
	}
	if in.ServerTLS == nil || in.TLSNode == nil || in.Out == nil || in.Dispatch == nil || in.Admit == nil || in.PacketDispatch == nil {
		t.Fatalf("运行时输入不全: ServerTLS=%v Out=%v Dispatch=%v Admit=%v PacketDispatch=%v",
			in.ServerTLS != nil, in.Out != nil, in.Dispatch != nil, in.Admit != nil, in.PacketDispatch != nil)
	}
	if in.Node.Get("custom-knob").Str() != "on" {
		t.Fatalf("口内协议字段未进 Node: %q", in.Node.Get("custom-knob").Str())
	}
}

// 口内 users(垫片):标量字段原样作 Fields。
func TestSessionPluginInlineUsers(t *testing.T) {
	capturedIn = nil
	buildYAML(t, `
inbounds:
  - name: fs-in
    type: fakesess
    listen: 127.0.0.1:0
    users:
      - uuid: 22222222-2222-2222-2222-222222222222
        password: pw-b
        name: bob
outbounds:
  - name: direct
    type: direct
`)
	if len(capturedIn) != 1 || len(capturedIn[0].Users) != 1 {
		t.Fatalf("口内用户未交插件: %+v", capturedIn)
	}
	u := capturedIn[0].Users[0]
	if u.Tag != "bob" || u.Fields["uuid"] != "22222222-2222-2222-2222-222222222222" || u.Secret != "pw-b" {
		t.Fatalf("口内用户打包错: %+v", u)
	}
}

// 出站:具名字段(server/secret/uuid/sni/insecure)被 yaml 截胡出 Extra 后须补回 Node,未声明键原样进 Node。
func TestSessionPluginOutboundNode(t *testing.T) {
	capturedOut = nil
	buildYAML(t, `
inbounds:
  - name: s5
    type: socks
    listen: 127.0.0.1:0
    outbound: fs-out
outbounds:
  - name: fs-out
    type: fakesess
    server: example.com:443
    uuid: 33333333-3333-3333-3333-333333333333
    secret: pw-c
    sni: sni.example.com
    insecure: true
    alpn:
      - h3
`)
	if len(capturedOut) != 1 {
		t.Fatalf("插件 NewOutbound 调用 %d 次,期望 1", len(capturedOut))
	}
	n := capturedOut[0]
	for k, want := range map[string]string{
		"server": "example.com:443", "uuid": "33333333-3333-3333-3333-333333333333",
		"secret": "pw-c", "sni": "sni.example.com", "insecure": "true",
	} {
		if got := n.Get(k).Str(); got != want {
			t.Errorf("出站 Node[%s]=%q,期望 %q", k, got, want)
		}
	}
	if a := n.Get("alpn"); a == nil || a.Kind != spec.KindSeq || len(a.Seq) != 1 || a.Seq[0].Str() != "h3" {
		t.Errorf("未声明键 alpn 未原样进 Node: %+v", a)
	}
}

// 运行时托管 TCP 监听形态(NewHandler):插件产出 handler,落到通用收尾成为 Instance.Handler。
var capturedHandlerIn []registry.SessionInbound

type nopHandler struct{}

func (nopHandler) HandleStream(context.Context, link.Stream, *endpoint.Metadata) error { return nil }
func (nopHandler) HandlePacket(context.Context, link.PacketConn, *endpoint.Metadata) error {
	return nil
}

func init() {
	registry.RegisterSession(registry.Session{
		Name: "fakehandler",
		NewHandler: func(in registry.SessionInbound) (endpoint.InboundHandler, error) {
			capturedHandlerIn = append(capturedHandlerIn, in)
			return nopHandler{}, nil
		},
		UserFromContext: func(context.Context) (string, bool) { return "", false },
	})
}

func TestSessionPluginHandlerForm(t *testing.T) {
	capturedHandlerIn = nil
	var f File
	if err := yaml.Unmarshal([]byte(`
users:
  - name: carol
    keys:
      fakehandler: secret-c
inbounds:
  - name: fh-in
    type: fakehandler
    listen: 127.0.0.1:0
outbounds:
  - name: direct
    type: direct
`), &f); err != nil {
		t.Fatal(err)
	}
	insts, err := f.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(capturedHandlerIn) != 1 || len(capturedHandlerIn[0].Users) != 1 {
		t.Fatalf("NewHandler 未按期调用: %+v", capturedHandlerIn)
	}
	if u := capturedHandlerIn[0].Users[0]; u.Tag != "carol@fh-in" || u.Secret != "secret-c" {
		t.Fatalf("标量键用户打包错: %+v", u)
	}
	found := false
	for _, it := range insts {
		if _, ok := it.Handler.(nopHandler); ok && it.Run == nil {
			found = true
		}
	}
	if !found {
		t.Fatal("handler 形态插件未成为 Instance.Handler(应交运行时 TCP 接入环托管)")
	}
}

// 反连 portal 口:运行时不给 Admit(portal 流不得在本机自管 relay 落地),Dispatch / PacketDispatch 都改派进隧道。
func TestSessionPluginPortalMode(t *testing.T) {
	capturedIn = nil
	buildYAML(t, `
inbounds:
  - name: fs-portal
    type: fakesess
    mode: portal
    control-domain: reverse.test
    listen: 127.0.0.1:0
    users:
      - name: dave
        password: pw-d
outbounds:
  - name: direct
    type: direct
`)
	if len(capturedIn) != 1 {
		t.Fatalf("插件 NewInbound 调用 %d 次,期望 1", len(capturedIn))
	}
	in := capturedIn[0]
	if in.Admit != nil {
		t.Fatal("portal 口不应给 Admit(流须改派进隧道)")
	}
	if in.Dispatch == nil || in.PacketDispatch == nil {
		t.Fatalf("portal 口须给 Dispatch/PacketDispatch: Dispatch=%v PacketDispatch=%v", in.Dispatch != nil, in.PacketDispatch != nil)
	}
}

// connect-ip(整包 L3 隧道)不能当反连 portal:运行时不给 AdmitTunnel,插件明确报错而非静默忽略 mode: portal。
func TestConnectIPPortalRejected(t *testing.T) {
	var f File
	if err := yaml.Unmarshal([]byte(`
inbounds:
  - name: cip-portal
    type: connect-ip
    mode: portal
    listen: 127.0.0.1:0
outbounds:
  - name: direct
    type: direct
`), &f); err != nil {
		t.Fatal(err)
	}
	_, err := f.Build(context.Background())
	if err == nil || !strings.Contains(err.Error(), "portal") {
		t.Fatalf("connect-ip 当 portal 应报错,得到 %v", err)
	}
}
