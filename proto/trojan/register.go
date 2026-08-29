package trojan

import (
	"github.com/LOVECHEN/ntr/core/cap"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// Parse:Trojan 无自有线上参数(鉴权在外部 Authenticator)。
func Parse(*spec.Node) (Config, error) { return Config{}, nil }

// 注册 Trojan 的 Descriptor —— manifest 一行 blank-import 即链接进来。
// Requires SecureCarrier:Trojan 是「看起来像 HTTPS」的薄鉴权,必须叠在提供机密性的下层
// (TLS/REALITY)之上;裸 TCP 明文跑无意义 → 编译期判死(关联表约束)。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:     "trojan",
		Display:  "Trojan",
		Band:     registry.BandProxy,
		In:       []registry.Sort{registry.SortStream},
		Out:      registry.SortStream,
		Requires: []cap.ID{cap.IDSecureCarrier}, // 必须有 tls/reality 在下
		Reload:   registry.ReloadDrain,
		Parse:    Parse,
		Build:    Build,
	})
}
