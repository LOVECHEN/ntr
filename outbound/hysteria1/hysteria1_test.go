package hysteria1

import (
	"testing"

	"github.com/LOVECHEN/ntr/core/endpoint"
)

// TestNewOutboundConstructs:出站构造无误且实现 endpoint.Outbound(带宽缺省填充、aTLS 适配装配;
// 完整 QUIC 往返由 Docker 互通测试覆盖:NTR 客户端 → 官方 hysteria v1.3.5 服务端)。
func TestNewOutboundConstructs(t *testing.T) {
	out, err := NewOutbound(Options{Server: "127.0.0.1:10000", Password: "pw", SNI: "example.com", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := interface{}(out).(endpoint.Outbound); !ok {
		t.Fatal("未实现 endpoint.Outbound")
	}
}

// TestMbpsToBPS:Mbps→字节/秒 换算正确(100 Mbps = 12.5 MB/s)。
func TestMbpsToBPS(t *testing.T) {
	if got := mbpsToBPS(100); got != 12_500_000 {
		t.Fatalf("mbpsToBPS(100) = %d, want 12500000", got)
	}
}
