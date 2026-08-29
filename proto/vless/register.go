package vless

import "github.com/LOVECHEN/ntr/core/registry"

// 在 init() 里注册 VLESS 的 Descriptor —— manifest/ 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "vless",
		Display: "VLESS",
		Band:    registry.BandProxy,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain, // 改凭据/口 = 只断该单元
		Parse:   Parse,
		Build:   Build,
	})
}
