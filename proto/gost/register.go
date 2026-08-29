package gost

import (
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// Parse 解 gost relay 配置:可选 username/password(gost relay 的简单鉴权,置空则不鉴权)。
func Parse(n *spec.Node) (Config, error) {
	return Config{
		Username: n.Get("username").Str(),
		Password: n.Get("password").Str(),
	}, nil
}

// 注册 gost relay(BandProxy)。gost relay 自身无加密,可裸跑(不安全)或叠 [tls, gost] / [ws, tls, gost] /
// mux —— 故不 Requires SecureCarrier(与 mihomo type: gost-relay 允许无 tls 一致)。manifest blank-import 链入。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:    "gost",
		Display: "gost relay",
		Band:    registry.BandProxy,
		In:      []registry.Sort{registry.SortStream},
		Out:     registry.SortStream,
		Reload:  registry.ReloadDrain,
		Parse:   Parse,
		Build:   Build,
	})
}
