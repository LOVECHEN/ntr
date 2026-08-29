package shadowtls

import (
	"github.com/LOVECHEN/ntr/core/registry"
)

// 注册 ShadowTLS 传输层(Band=CryptoObfs,居 Crypto 之上、Frame 之下的抗探测伪装槽)。
// 不 Provides SecureCarrier:ShadowTLS 只做抗探测伪装 + 完整性,内层机密性靠上层协议
// (惯用 [shadowtls, shadowsocks])。manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "shadowtls",
		Display: "ShadowTLS",
		Band:    registry.BandCryptoObfs,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
