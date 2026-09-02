package config

import (
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// TestUsersParse 验证顶层 users 全块式解析:平铺 keys(单层标量/轮换列表)、
// on/off/all 访问控制(缺省=全开、on:all 保留字、on:[口]白名单、off 黑名单)。
func TestUsersParse(t *testing.T) {
	const src = `
users:
  - name: vip                    # 缺省 on = 全开(= on: all)
    keys:
      vless: 550e8400-uuid
      shadowtls: alice-pw        # 平铺;shadowtls+snell 组合由口的栈决定
      snell: alice-psk
  - name: basic
    on: all                      # 保留字:显式全开(可省)
    off:
      - stls3-snell6             # 从全开里屏蔽这个口
    keys:
      vless:
        - uuid-old
        - uuid-new               # 轮换:零断连过渡
  - name: guest
    on:
      - vless-in                 # 白名单收窄:只这个口
    keys:
      vless: guest-uuid
`
	var f File
	if err := yaml.Unmarshal([]byte(src), &f); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(f.Users) != 3 {
		t.Fatalf("users 数错: %d", len(f.Users))
	}

	// vip:缺省 on → 全开;平铺 keys 三把
	vip := f.Users[0]
	if !vip.AllowsAllInbounds() {
		t.Error("vip 缺省 on 应为全开")
	}
	if vip.Keys["vless"].Values[0] != "550e8400-uuid" {
		t.Errorf("vip vless 单层错: %+v", vip.Keys["vless"])
	}
	if vip.Keys["shadowtls"].Values[0] != "alice-pw" || vip.Keys["snell"].Values[0] != "alice-psk" {
		t.Error("shadowtls/snell 平铺解析错")
	}

	// basic:on:all → 全开;off 黑名单;vless 轮换列表
	basic := f.Users[1]
	if !basic.AllowsAllInbounds() {
		t.Error("basic on:all 应为全开")
	}
	if len(basic.Off) != 1 || basic.Off[0] != "stls3-snell6" {
		t.Errorf("off 黑名单解析错: %v", basic.Off)
	}
	if got := basic.Keys["vless"].Values; len(got) != 2 || got[0] != "uuid-old" || got[1] != "uuid-new" {
		t.Errorf("vless 轮换列表解析错: %v", got)
	}

	// guest:on:[vless-in] → 白名单(非全开)
	guest := f.Users[2]
	if guest.AllowsAllInbounds() {
		t.Error("guest on:[vless-in] 不应为全开")
	}
	if len(guest.On) != 1 || guest.On[0] != "vless-in" {
		t.Errorf("白名单解析错: %v", guest.On)
	}
}
