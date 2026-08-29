package snell

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 Snell 的 Descriptor(v1-v6 全版本)—— manifest/ 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "snell",
		Display: "Snell (v1-v6)",
		Band:    registry.BandProxy,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain, // 改 PSK/口 = 只断该单元
		Parse:   Parse,
		Build:   Build,
	})
}
