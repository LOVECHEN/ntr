package quic

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 QUIC 独立传输(Band=Base,UDP-base 可靠多流,内建 TLS)。产 BaseTransport;叠法 [quic, vless]。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "quic",
		Display: "QUIC (V2Ray)",
		Band:    registry.BandBase,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
