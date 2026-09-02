package config

import (
	"context"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// TestListenAddrIdempotent:Build 把合成结果写回 in.Listen 后再调 listenAddr,必须得到同一值
// (审计抓的 P0:之前第二次会拼成 "[0.0.0.0:2053]:2053",口名对不上、凭据静默丢失)。
func TestListenAddrIdempotent(t *testing.T) {
	in := Inbound{Listen: "0.0.0.0", Port: 2053}
	first := in.listenAddr()
	if first != "0.0.0.0:2053" {
		t.Fatalf("首次合成错: %q", first)
	}
	in.Listen = first // 模拟 Build 的原地写回(Port 仍为 2053)
	if again := in.listenAddr(); again != first {
		t.Errorf("listenAddr 不幂等: 第一次 %q 第二次 %q", first, again)
	}
	// 旧格式 host:port、Port=0:原样
	if got := (Inbound{Listen: "127.0.0.1:1080"}).listenAddr(); got != "127.0.0.1:1080" {
		t.Errorf("旧格式应原样: %q", got)
	}
	// 无 listen 只有 port:缺省 0.0.0.0
	if got := (Inbound{Port: 443}).listenAddr(); got != "0.0.0.0:443" {
		t.Errorf("缺省 host 错: %q", got)
	}
}

// TestNewFormatRequiresName:新格式口是 users.on / BillID 的锚点,缺 name 必须在 Build 期报错,
// 不能静默退回监听地址当口名。
func TestNewFormatRequiresName(t *testing.T) {
	const src = `
inbounds:
  - type: vless
    port: 2053
users:
  - name: alice
    keys:
      vless: 550e8400-e29b-41d4-a716-446655440000
`
	var f File
	if err := yaml.Unmarshal([]byte(src), &f); err != nil {
		t.Fatalf("解析: %v", err)
	}
	_, err := f.Build(context.Background())
	if err == nil || !strings.Contains(err.Error(), "E-INBOUND-NONAME") {
		t.Fatalf("新格式口缺 name 应报 E-INBOUND-NONAME: %v", err)
	}
}
