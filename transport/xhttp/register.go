package xhttp

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 XHTTP(SplitHTTP)传输层(Band=Frame)。stream-one 模式:h2c 单请求全双工,契合 StreamTransport。
// 惯用叠法 [tls, xhttp, vless]。manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "xhttp",
		Display: "XHTTP (SplitHTTP stream-one)",
		Band:    registry.BandFrame,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
