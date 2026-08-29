package e2e

import (
	"testing"

	"github.com/LOVECHEN/ntr/core/compile"
	"github.com/LOVECHEN/ntr/core/registry"
	_ "github.com/LOVECHEN/ntr/manifest"
)

// TestLayerConstraints:关联表在编译期强制——非法层组合被 compile.Order 大声判死,
// 不留到运行期。直接测 compile.Order(只校验层组合约束,不建栈)。
func TestLayerConstraints(t *testing.T) {
	order := func(names ...string) error {
		descs := make([]registry.AnyDescriptor, len(names))
		for i, n := range names {
			d, ok := registry.Lookup(n)
			if !ok {
				t.Fatalf("%q 未注册", n)
			}
			descs[i] = d
		}
		_, err := compile.Order(descs)
		return err
	}

	cases := []struct {
		name   string
		layers []string
		wantOK bool
	}{
		{"trojan 裸跑(缺加密层)→ 判死", []string{"trojan"}, false},
		{"tls→trojan 合法", []string{"tls", "trojan"}, true},
		{"reality→trojan 合法(REALITY 非 vless 独占)", []string{"reality", "trojan"}, true},
		{"tls→vless 合法", []string{"tls", "vless"}, true},
		{"reality→vless 合法(标配)", []string{"reality", "vless"}, true},
		{"vless 裸跑合法(无加密要求)", []string{"vless"}, true},
		{"tls+reality 同 band 互斥 → 判死", []string{"tls", "reality"}, false},
		{"shadowsocks 裸跑合法(自带 AEAD)", []string{"shadowsocks"}, true},
		{"snell 裸跑合法(自带 AEAD)", []string{"snell"}, true},
		{"shadowtls→shadowsocks 合法(惯用叠法)", []string{"shadowtls", "shadowsocks"}, true},
		{"tls→httpupgrade→vless 合法(过 CDN 三层栈)", []string{"tls", "httpupgrade", "vless"}, true},
		{"httpupgrade→vmess 合法(Frame 层承载代理)", []string{"httpupgrade", "vmess"}, true},
		{"tls→ws→vless 合法(标准过 CDN 栈)", []string{"tls", "ws", "vless"}, true},
		{"tls→grpc→vless 合法(gRPC over TLS 栈)", []string{"tls", "grpc", "vless"}, true},
		{"grpc→trojan 判死(grpc 只分帧不提供机密性)", []string{"grpc", "trojan"}, false},
		{"ws→trojan 判死(ws 只分帧不提供机密性,trojan 需 SecureCarrier)", []string{"ws", "trojan"}, false},
		{"tls→ws→trojan 合法(tls 补足 SecureCarrier)", []string{"tls", "ws", "trojan"}, true},
		{"vmess 裸跑合法(自带 AEAD)", []string{"vmess"}, true},
		{"tls→vmess 合法", []string{"tls", "vmess"}, true},
		{"http 裸跑合法(本地明文代理入站)", []string{"http"}, true},
		{"tls→http 合法(HTTPS 代理入站)", []string{"tls", "http"}, true},
	}
	for _, c := range cases {
		err := order(c.layers...)
		if c.wantOK && err != nil {
			t.Errorf("%s:期望通过,却报错:%v", c.name, err)
		}
		if !c.wantOK && err == nil {
			t.Errorf("%s:期望编译期判死,却通过了", c.name)
		}
	}
}
