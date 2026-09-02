package config

import (
	"context"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// TestUsersOnProtoWithoutCodecFailsLoud:给既无 CredentialCodec 也无 UserRegistrar 的协议(ssr:key 即密钥,
// 单 principal 豁免)配了顶层 users,Build 必须报 E-USERS-NO-CODEC,不能把 binding 静默丢掉落 Ambient
// (冻结律#6)。同一口不配 users 则照常成功。
func TestUsersOnProtoWithoutCodecFailsLoud(t *testing.T) {
	const withUsers = `
inbounds:
  - name: ssr-in
    type: ssr
    listen: 127.0.0.1
    port: 18080
    cipher: aes-256-cfb
    password: portpw
    protocol: origin
    obfs: plain
users:
  - name: alice
    keys:
      ssr: "alice-pw"
`
	var f File
	if err := yaml.Unmarshal([]byte(withUsers), &f); err != nil {
		t.Fatalf("解析: %v", err)
	}
	_, err := f.Build(context.Background())
	if err == nil || !strings.Contains(err.Error(), "E-USERS-NO-CODEC") {
		t.Fatalf("配了 users 但协议无 codec/registrar 应报 E-USERS-NO-CODEC: %v", err)
	}

	const noUsers = `
inbounds:
  - name: ssr-in
    type: ssr
    listen: 127.0.0.1
    port: 18080
    cipher: aes-256-cfb
    password: portpw
    protocol: origin
    obfs: plain
`
	var g File
	if err := yaml.Unmarshal([]byte(noUsers), &g); err != nil {
		t.Fatalf("解析: %v", err)
	}
	if _, err := g.Build(context.Background()); err != nil {
		t.Fatalf("未配 users 的 ssr 口应照常 Build: %v", err)
	}
}
