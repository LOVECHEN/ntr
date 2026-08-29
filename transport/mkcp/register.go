package mkcp

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 mKCP 传输层(Band=Base,居栈底 —— UDP-base 可靠传输,替代 TCP)。产 BaseTransport;
// 惯用叠法 [mkcp, vless]。manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "mkcp",
		Display: "mKCP (reliable-UDP)",
		Band:    registry.BandBase,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
