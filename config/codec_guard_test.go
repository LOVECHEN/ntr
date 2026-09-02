package config

import (
	"context"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// TestUsersOnProtoWithoutCodecFailsLoud:给不支持 per-user 凭据的协议(mixed 无 CredentialCodec,
// 本地 no-auth 入站)配了顶层 users,Build 必须报 E-USERS-NO-CODEC,不能把 binding 静默丢掉落 Ambient
// (冻结律#6)。同一口不配 users 则照常成功。
func TestUsersOnProtoWithoutCodecFailsLoud(t *testing.T) {
	const withUsers = `
inbounds:
  - name: mixed-in
    type: mixed
    listen: 127.0.0.1
    port: 18080
users:
  - name: alice
    keys:
      mixed: "alice:pw"
`
	var f File
	if err := yaml.Unmarshal([]byte(withUsers), &f); err != nil {
		t.Fatalf("解析: %v", err)
	}
	_, err := f.Build(context.Background())
	if err == nil || !strings.Contains(err.Error(), "E-USERS-NO-CODEC") {
		t.Fatalf("配了 users 但协议无 codec 应报 E-USERS-NO-CODEC: %v", err)
	}

	const noUsers = `
inbounds:
  - name: mixed-in
    type: mixed
    listen: 127.0.0.1
    port: 18080
`
	var g File
	if err := yaml.Unmarshal([]byte(noUsers), &g); err != nil {
		t.Fatalf("解析: %v", err)
	}
	if _, err := g.Build(context.Background()); err != nil {
		t.Fatalf("未配 users 的 http 口应照常 Build: %v", err)
	}
}
