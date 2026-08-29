package mixed

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 mixed 的 Descriptor —— manifest 一行 blank-import 即链接进来。
// 与 socks/http 同属 Proxy 波段;自身无线格式,只做首字节分派。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "mixed",
		Display: "Mixed (SOCKS4/4a/5 + HTTP on one port)",
		Band:    registry.BandProxy,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
