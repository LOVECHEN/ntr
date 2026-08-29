package grpc

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 gRPC(Gun)传输层(Band=Frame,同 ws/httpupgrade)。不 Provides/Requires 能力:只分帧穿透,
// 机密性靠上层。惯用叠法 [tls(alpn h2), grpc, vless]。manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "grpc",
		Display: "gRPC (Gun)",
		Band:    registry.BandFrame,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
