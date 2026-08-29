package obfs

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 simple-obfs 伪装(Band=Frame),两种模式:http(首包裹假 HTTP、之后裸流)与 tls
// (假 TLS 握手 + application-data 记录)。惯用叠法 [obfs, shadowsocks]。manifest 一行 blank-import 链接。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "obfs",
		Display: "simple-obfs (HTTP/TLS)",
		Band:    registry.BandFrame,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
