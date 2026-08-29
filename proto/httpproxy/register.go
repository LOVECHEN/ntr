package httpproxy

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 HTTP 代理(Band=Proxy)。可裸跑(本地明文 http 代理入站,同 socks)或叠 [tls, http]。
// 不 Requires SecureCarrier:本地入站/明文代理是常规用法。manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "http",
		Display: "HTTP Proxy",
		Band:    registry.BandProxy,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
