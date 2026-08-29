package shadowtls

import (
	"context"
	"testing"

	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
)

// TestParseDefaults:version 缺省应为 3。
func TestParseDefaults(t *testing.T) {
	node := &spec.Node{Kind: spec.KindMap, Map: map[string]*spec.Node{
		"password": spec.Scalar("p"),
		"sni":      spec.Scalar("www.apple.com"),
	}}
	cfg, err := Parse(node)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 3 {
		t.Fatalf("version 缺省 = %d, want 3", cfg.Version)
	}
	if cfg.Password != "p" || cfg.SNI != "www.apple.com" {
		t.Fatalf("解析字段错:%+v", cfg)
	}
}

// TestBuildConstructs:v2/v3 都能构造出 Transport 且实现 StreamTransport(隔离验证 sing-shadowtls
// 客户端/服务端句柄装配无误;完整协议往返由 Docker 互通测试覆盖:mihomo ss+shadow-tls → NTR)。
func TestBuildConstructs(t *testing.T) {
	for _, v := range []int{2, 3} {
		got, err := Build(context.Background(), Config{Version: v, Password: "pw", SNI: "www.apple.com", Handshake: "www.apple.com:443"}, nil)
		if err != nil {
			t.Fatalf("v%d Build: %v", v, err)
		}
		if _, ok := got.(transport.StreamTransport); !ok {
			t.Fatalf("v%d 未实现 StreamTransport", v)
		}
	}
}
