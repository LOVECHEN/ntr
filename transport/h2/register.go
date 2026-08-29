package h2

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 HTTP/2 传输层(Band=Frame)。V2Ray 的 "http" network:h2/h2c 单请求全双工,契合 StreamTransport。
// 名取 h2(避开 http 代理协议名)。惯用叠法 [tls, h2, vless]。manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "h2",
		Display: "HTTP/2 (V2Ray http)",
		Band:    registry.BandFrame,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
