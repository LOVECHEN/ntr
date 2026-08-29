package socks

import (
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// Parse:SOCKS5 no-auth 无自有线上参数。
func Parse(*spec.Node) (Config, error) { return Config{}, nil }

// 注册 SOCKS5 的 Descriptor —— manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "socks",
		Display: "SOCKS5",
		Band:    registry.BandProxy,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
