package vlessenc

import "github.com/LOVECHEN/ntr/core/registry"

// 注册 VLESS Encryption(Band=Crypto)。后量子加密层,叠法 [vlessenc, vless]。
// manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "vlessenc",
		Display: "VLESS Encryption (ML-KEM-768 + X25519)",
		Band:    registry.BandCrypto,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
