package manifest_test

import (
	"testing"

	"github.com/LOVECHEN/ntr/core/registry"

	// blank-import manifest 触发所有协议的 init() 注册。
	_ "github.com/LOVECHEN/ntr/manifest"
)

// TestManifestRegisters 验证 manifest 一行 blank-import 把协议装进注册表。
func TestManifestRegisters(t *testing.T) {
	for _, name := range []string{"vless", "snell"} {
		d, ok := registry.Lookup(name)
		if !ok {
			t.Errorf("%q not registered via manifest", name)
			continue
		}
		if d.Band() != registry.BandProxy {
			t.Errorf("%q band = %d, want BandProxy(60)", name, d.Band())
		}
	}
}
