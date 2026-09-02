package config

import (
	"testing"

	"github.com/LOVECHEN/ntr/core/principal"
)

// identityCanon 测试用:secret 原样作 key(不派生),便于断言。
func identityCanon(proto, secret string) ([]byte, error) { return []byte(secret), nil }

func TestDesugar(t *testing.T) {
	inboundNames := map[string]bool{"vless-in": true, "stls-snell-in": true, "ss-in": true}
	// 口 → 认证协议(按栈序,外→内):单层 / 多层 / 单层
	stackProtos := map[string][]string{
		"vless-in":      {"vless"},
		"stls-snell-in": {"shadowtls", "snell"},
		"ss-in":         {"shadowsocks"},
	}
	users := []User{
		{ // 缺省 on = 全开;有 vless/shadowtls/snell,没 ss
			Name: "alice", Rate: "200mbps", MaxIPs: 8,
			Keys: map[string]KeySpec{
				"vless":     {Values: []string{"alice-uuid"}},
				"shadowtls": {Values: []string{"alice-stls"}},
				"snell":     {Values: []string{"alice-snell"}},
			},
		},
		{ // on:all + off 屏蔽多层口;vless 轮换 2 把
			Name: "bob", On: NameList{"all"}, Off: NameList{"stls-snell-in"},
			Keys: map[string]KeySpec{"vless": {Values: []string{"bob-1", "bob-2"}}},
		},
		{ // on:[vless-in] 白名单
			Name: "guest", On: NameList{"vless-in"},
			Keys: map[string]KeySpec{"vless": {Values: []string{"guest-uuid"}}},
		},
	}

	binds, err := Desugar(users, inboundNames, stackProtos, identityCanon)
	if err != nil {
		t.Fatalf("Desugar 失败: %v", err)
	}
	byBill := map[string][]principal.CredBinding{}
	for _, b := range binds {
		byBill[b.BillID] = append(byBill[b.BillID], b)
	}

	// alice 全开:vless-in 单层 + stls-snell-in 多层;ss-in 缺密钥跳过
	av := byBill["alice@vless-in"]
	if len(av) != 1 || len(av[0].Layers) != 1 || av[0].Layers[0].Scheme != "vless" || string(av[0].Layers[0].Key) != "alice-uuid" {
		t.Errorf("alice@vless-in 单层错: %+v", av)
	}
	as := byBill["alice@stls-snell-in"]
	if len(as) != 1 || len(as[0].Layers) != 2 {
		t.Fatalf("alice@stls-snell-in 应 2 层: %+v", as)
	}
	if as[0].Layers[0].Scheme != "shadowtls" || as[0].Layers[1].Scheme != "snell" {
		t.Errorf("多层栈序应 shadowtls→snell: %v", as[0].Layers)
	}
	if _, ok := byBill["alice@ss-in"]; ok {
		t.Error("alice 无 ss 密钥,全开下 ss-in 应跳过")
	}
	// LimitRef 该 user 全部 binding 共指同一个
	if av[0].Limit == nil || as[0].Limit != av[0].Limit {
		t.Error("alice 全部 binding 应共指同一 LimitRef")
	}
	if av[0].Limit.MaxIPs != 8 || av[0].Limit.Rate != 25_000_000 { // 200mbps → 25e6 bytes/s
		t.Errorf("alice LimitRef 错: %+v", av[0].Limit)
	}

	// bob:on:all - off(stls-snell-in);vless 轮换 → 2 个平行 binding 共享 BillID;无 ss 密钥
	bv := byBill["bob@vless-in"]
	if len(bv) != 2 {
		t.Errorf("bob 轮换应产 2 个平行 binding: %d", len(bv))
	}
	if _, ok := byBill["bob@stls-snell-in"]; ok {
		t.Error("bob off 了 stls-snell-in,不应产 binding")
	}
	if bv[0].Limit != nil {
		t.Error("bob 无限制,LimitRef 应 nil")
	}

	// guest:白名单只 vless-in
	if len(byBill["guest@vless-in"]) != 1 {
		t.Error("guest 白名单应只 vless-in")
	}
	if _, ok := byBill["guest@stls-snell-in"]; ok {
		t.Error("guest 白名单不应有 stls-snell-in")
	}
}

// TestDesugarKeyMissing:显式 on 了某口但缺该口密钥 → E-KEY-MISSING(全开则静默跳过)。
func TestDesugarKeyMissing(t *testing.T) {
	inboundNames := map[string]bool{"vless-in": true}
	stackProtos := map[string][]string{"vless-in": {"vless"}}

	// 显式 on 缺密钥 → 报错
	explicit := []User{{Name: "x", On: NameList{"vless-in"}, Keys: map[string]KeySpec{}}}
	if _, err := Desugar(explicit, inboundNames, stackProtos, identityCanon); err == nil {
		t.Error("显式 on 缺密钥应报 E-KEY-MISSING")
	}

	// 全开缺密钥 → 静默跳过,不报错、不产 binding
	allOpen := []User{{Name: "y", Keys: map[string]KeySpec{}}}
	binds, err := Desugar(allOpen, inboundNames, stackProtos, identityCanon)
	if err != nil {
		t.Errorf("全开缺密钥不应报错: %v", err)
	}
	if len(binds) != 0 {
		t.Errorf("全开缺密钥不应产 binding: %d", len(binds))
	}
}
