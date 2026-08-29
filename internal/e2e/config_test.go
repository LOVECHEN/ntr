package e2e

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/config"
	"github.com/LOVECHEN/ntr/core/spec"
	_ "github.com/LOVECHEN/ntr/manifest"
	"github.com/LOVECHEN/ntr/service"
)

const configYAML = `
inbounds:
  - listen: 127.0.0.1:0
    layers:
      - { type: tls }
      - { type: vless }
    users:
      - { uuid: "00112233-4455-6677-8899-aabbccddeeff" }
    outbound: direct
outbounds:
  - { name: direct, type: direct }
`

// TestConfigFileEndToEnd:YAML 配置 → config.Build 装配入站栈([tls→vless]+具名用户)→
// serve;真实客户端([tls→vless] 出站,凭配置里的 UUID)穿过打 echo。声明式部署路径全通。
func TestConfigFileEndToEnd(t *testing.T) {
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

	// 写配置文件并装配。
	dir := t.TempDir()
	path := filepath.Join(dir, "ntr.yaml")
	if err := os.WriteFile(path, []byte(configYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	insts, err := f.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(insts) != 1 {
		t.Fatalf("期望 1 个入站,得到 %d", len(insts))
	}

	srvLn, err := net.Listen("tcp", insts[0].Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer srvLn.Close()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = service.Serve(sctx, srvLn, insts[0].Handler) }()

	// 真实客户端:出站栈用配置里的 UUID 作 secret。
	out, err := service.BuildOutbound(ctx, srvLn.Addr().String(),
		[]service.LayerSpec{
			{Name: "tls", Node: mapScalar("sni", "localhost", "insecure", "true")},
			{Name: "vless", Node: &spec.Node{Kind: spec.KindMap}},
		},
		"00112233-4455-6677-8899-aabbccddeeff",
	)
	if err != nil {
		t.Fatal(err)
	}

	stream, err := out.DialStream(ctx, echoDst)
	if err != nil {
		t.Fatalf("出站拨号:%v", err)
	}
	defer stream.Close()

	const msg = "hello through YAML-configured ntr"
	if _, err := stream.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

// TestConfigUnknownUserRejected:配置里没登记的 UUID → 服务端握手拒绝。
func TestConfigUnknownUserRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ntr.yaml")
	if err := os.WriteFile(path, []byte(configYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	f, _ := config.Load(path)
	insts, err := f.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	srvLn, _ := net.Listen("tcp", insts[0].Listen)
	defer srvLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = service.Serve(ctx, srvLn, insts[0].Handler) }()

	out, err := service.BuildOutbound(ctx, srvLn.Addr().String(),
		[]service.LayerSpec{
			{Name: "tls", Node: mapScalar("sni", "localhost", "insecure", "true")},
			{Name: "vless", Node: &spec.Node{Kind: spec.KindMap}},
		},
		"ffffffff-ffff-ffff-ffff-ffffffffffff", // 未登记
	)
	if err != nil {
		t.Fatal(err)
	}
	// DialStream 只写 VLESS 头即返回;拒绝在服务端握手时发生 → 客户端读时才见断连。
	stream, err := out.DialStream(ctx, addr.FromFqdn("x", 1))
	if err != nil {
		return // 若实现变为握手即拒绝,也算通过
	}
	defer stream.Close()
	_, _ = stream.Write([]byte("x"))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(stream, buf); err == nil {
		t.Fatal("未登记 UUID 竟拿到回程数据;应被服务端拒绝断连")
	}
}
