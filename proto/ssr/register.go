package ssr

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 SSR 的 Descriptor —— manifest 一行 blank-import 即链接进来。
// 客户端(全插件)+ 服务端(plain obfs + origin/auth_aes128_sha1/auth_aes128_md5 protocol,自写逆向);
// In=Stream(可作入站,叠在 tcp 之上)、Out=Stream(出站)。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "ssr",
		Display: "ShadowsocksR",
		Band:    registry.BandProxy,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
