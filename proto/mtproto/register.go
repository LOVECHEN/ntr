package mtproto

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 MTProto 的 Descriptor —— manifest 一行 blank-import 即链接进来。
// 自带 faketls 伪装与 obfuscated2 加密,故 Requires 留空(不需要下层再叠 tls/reality)。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "mtproto",
		Display: "MTProto Proxy (faketls)",
		Band:    registry.BandProxy,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
