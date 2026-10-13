package domainsocket

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 DomainSocket 传输层(Band=Base,居栈底 —— 以 unix 套接字替代 TCP)。产 BaseTransport;
// 惯用叠法 [domainsocket, vless] 或 [domainsocket, tls, trojan]。manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "domainsocket",
		Display: "DomainSocket (unix socket)",
		Band:    registry.BandBase,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
