package httpupgrade

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 HTTPUpgrade 传输层(Band=Frame,居 Crypto 与 Proxy 之间)。不 Provides/Requires 任何
// 能力:只做 HTTP Upgrade 分帧穿透,机密性靠上层。惯用叠法 [tls, httpupgrade, vless]。
// manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "httpupgrade",
		Display: "HTTPUpgrade",
		Band:    registry.BandFrame,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
