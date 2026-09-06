package config

import (
	"testing"

	"github.com/LOVECHEN/ntr/core/principal"
)

// TestCredHashFoldedIntoInboundHash 守凭据级热重载 Tier-1 止血:口的 Instance Hash 必须把【有效凭据集】
// (顶层 users 脱糖出的 CredBinding)折进去 —— 否则改顶层 users/keys 只动 f.Users 不翻口 Hash,
// SIGHUP apply 静默 no-op,轮换/吊销在活口上被无视。本测锚定 Build 里 inboundHash 用的同一复合 hashOf。
func TestCredHashFoldedIntoInboundHash(t *testing.T) {
	in := Inbound{Name: "srv-in", Type: "vless", Listen: "0.0.0.0:443"}
	composite := func(key string) string {
		binds := []principal.CredBinding{{
			Inbound: "srv-in",
			BillID:  "alice@srv-in",
			Name:    "alice",
			Layers:  []principal.AuthLayer{{Scheme: "vless", Key: []byte(key)}},
		}}
		return hashOf(struct {
			In    Inbound
			Binds []principal.CredBinding
		}{in, binds})
	}

	// ① 只改凭据 key(口形态不变)→ 复合 hash 必变(否则热重载对该口 no-op = footgun)
	if composite("keyA") == composite("keyB") {
		t.Fatal("改顶层 user 的 key 后复合 hash 未变 → Tier-1 止血失效(轮换/吊销会被静默忽略)")
	}
	// ② binds 必须真进了 marshal:纯 in 的 hash ≠ 含 binds 的复合 hash(防 yaml.Marshal 落空致所有口同 hash)
	if hashOf(in) == composite("keyA") {
		t.Fatal("CredBinding 未影响 hash(marshal 可能失败落空)→ 折入无效")
	}
}
