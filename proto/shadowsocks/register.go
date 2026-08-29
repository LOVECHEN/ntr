package shadowsocks

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 Shadowsocks 的 Descriptor —— manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "shadowsocks",
		Display: "Shadowsocks 2022",
		Band:    registry.BandProxy,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
