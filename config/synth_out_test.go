package config

import (
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// TestSynthLayersOutboundNewFormat:出站新格式(type=协议名 + server/secret + tls:/ws: 层块 + flow)与等价
// 旧格式(type=proxy + layers 数组)产相同层集;direct/select/会话式 type 不判为新格式。
func TestSynthLayersOutboundNewFormat(t *testing.T) {
	const newFmt = `
outbounds:
  - name: up
    type: vless
    server: 1.2.3.4:443
    secret: 550e8400-e29b-41d4-a716-446655440000
    flow: xtls-rprx-vision
    tls:
      sni: example.com
      insecure: true
    ws:
      path: /ray
`
	const oldFmt = `
outbounds:
  - name: up
    type: proxy
    server: 1.2.3.4:443
    secret: 550e8400-e29b-41d4-a716-446655440000
    layers:
      - type: tls
        sni: example.com
        insecure: true
      - type: ws
        path: /ray
      - type: vless
        flow: xtls-rprx-vision
`
	var nf, of File
	if err := yaml.Unmarshal([]byte(newFmt), &nf); err != nil {
		t.Fatalf("新格式解析: %v", err)
	}
	if err := yaml.Unmarshal([]byte(oldFmt), &of); err != nil {
		t.Fatalf("旧格式解析: %v", err)
	}
	o := nf.Outbounds[0]
	if !o.newFormat() {
		t.Fatal("type=vless 出站应判为新格式")
	}
	if o.Server != "1.2.3.4:443" || o.Secret == "" {
		t.Errorf("server/secret 具名字段应保留: %+v", o)
	}
	if _, ok := o.Extra["tls"]; !ok {
		t.Error("出站无 tls 具名字段,tls: 应落 Extra")
	}
	ns, err := o.synthLayers()
	if err != nil {
		t.Fatalf("新格式 synthLayers: %v", err)
	}
	os_, err := of.Outbounds[0].synthLayers()
	if err != nil {
		t.Fatalf("旧格式 synthLayers: %v", err)
	}
	if layerNames(ns) != layerNames(os_) || layerNames(ns) != "tls,vless,ws" {
		t.Errorf("出站新旧层集不等或不为 tls,vless,ws:\n 新=%s\n 旧=%s", layerNames(ns), layerNames(os_))
	}
	if of.Outbounds[0].newFormat() {
		t.Error("旧格式出站(有 layers)不应判为新格式")
	}
	for _, typ := range []string{"direct", "", "block", "select", "urltest", "anytls", "hysteria2", "wireguard"} {
		if (Outbound{Type: typ}).newFormat() {
			t.Errorf("非协议 type=%q 不应判为新格式", typ)
		}
	}
}
