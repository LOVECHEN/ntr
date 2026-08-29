package ws

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 WebSocket 传输层(Band=Frame,居 Crypto 与 Proxy 之间)。不 Provides/Requires 任何能力:
// 只做 RFC 6455 分帧穿透,机密性靠上层。惯用叠法 [tls, ws, vless]。manifest 一行 blank-import。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "ws",
		Display: "WebSocket",
		Band:    registry.BandFrame,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
