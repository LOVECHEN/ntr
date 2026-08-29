package vmess

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 VMess 的 Descriptor —— manifest 一行 blank-import 即链接进来。
// VMess 自带 AEAD 载荷加密,裸 TCP 亦自securing,故不 Requires SecureCarrier(同 SS/Snell)。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "vmess",
		Display: "VMess (AEAD)",
		Band:    registry.BandProxy,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
