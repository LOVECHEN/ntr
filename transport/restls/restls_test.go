package restls

import (
	"context"
	"testing"

	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
)

// TestParse:解析字段。
func TestParse(t *testing.T) {
	node := &spec.Node{Kind: spec.KindMap, Map: map[string]*spec.Node{
		"server-name": spec.Scalar("www.microsoft.com"),
		"password":    spec.Scalar("pw"),
	}}
	cfg, err := Parse(node)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "www.microsoft.com" || cfg.Password != "pw" {
		t.Fatalf("解析字段错:%+v", cfg)
	}
}

// TestBuildConstructs:能构造出 Transport 且实现 StreamTransport(隔离验证 restls-client-go 客户端 config
// 模板 + 服务端 config 装配无误;完整握手往返由 Docker 互通测试覆盖:NTR↔NTR + mihomo restls 客户端 → NTR)。
func TestBuildConstructs(t *testing.T) {
	got, err := Build(context.Background(), Config{
		ServerName:   "www.microsoft.com",
		Password:     "pw",
		RestlsScript: "250?100<1,350~100<1,600~100,300~200,300~100",
	}, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, ok := got.(transport.StreamTransport); !ok {
		t.Fatal("未实现 StreamTransport")
	}
}
