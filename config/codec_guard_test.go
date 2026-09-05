package config

import (
	"context"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// TestUsersOnProtoWithoutCodecFailsLoud:给既无 CredentialCodec 也无 UserRegistrar 的协议(mtproto:secret
// 是口级单密钥,无 per-user 身份)配了顶层 users,Build 必须报 E-USERS-NO-CODEC,不能把 binding 静默丢掉
// 落 Ambient(冻结律#6)。同一口不配 users 则照常成功。
func TestUsersOnProtoWithoutCodecFailsLoud(t *testing.T) {
	const sec = "ee00112233445566778899aabbccddeeff676f6f676c652e636f6d" // 合法 ee-secret
	withUsers := `
inbounds:
  - name: mt-in
    type: mtproto
    listen: 127.0.0.1
    port: 18080
    secret: "` + sec + `"
users:
  - name: alice
    keys:
      mtproto: "` + sec + `"
`
	var f File
	if err := yaml.Unmarshal([]byte(withUsers), &f); err != nil {
		t.Fatalf("解析: %v", err)
	}
	_, err := f.Build(context.Background())
	if err == nil || !strings.Contains(err.Error(), "E-USERS-NO-CODEC") {
		t.Fatalf("配了 users 但协议无 codec/registrar 应报 E-USERS-NO-CODEC: %v", err)
	}

	noUsers := `
inbounds:
  - name: mt-in
    type: mtproto
    listen: 127.0.0.1
    port: 18080
    secret: "` + sec + `"
`
	var g File
	if err := yaml.Unmarshal([]byte(noUsers), &g); err != nil {
		t.Fatalf("解析: %v", err)
	}
	if _, err := g.Build(context.Background()); err != nil {
		t.Fatalf("未配 users 的 mtproto 口应照常 Build: %v", err)
	}
}
