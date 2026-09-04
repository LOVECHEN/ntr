package config

import (
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// TestSynthLayersOutboundNewFormat:出站第4章格式(type=协议名 + server/secret + tls:/ws: 层块 + flow)产
// 正确层集;direct/select/会话式 type 不判为新格式。
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
	var nf File
	if err := yaml.Unmarshal([]byte(newFmt), &nf); err != nil {
		t.Fatalf("新格式解析: %v", err)
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
		t.Fatalf("synthLayers: %v", err)
	}
	if layerNames(ns) != "tls,vless,ws" {
		t.Errorf("出站层集应为 tls,vless,ws: %s", layerNames(ns))
	}
	for _, typ := range []string{"direct", "", "block", "select", "urltest", "anytls", "hysteria2", "wireguard"} {
		if (Outbound{Type: typ}).newFormat() {
			t.Errorf("非协议 type=%q 不应判为新格式", typ)
		}
	}
}

// TestSynthLayersOutboundUUIDForwarded:`uuid:` 是 Outbound 的具名字段(tuic 用),yaml 具名优先会截胡;
// 流式新格式出站(vmess)的 uuid 必须转交进终端协议 Node,否则 vmess 客户端拿不到 uuid。
func TestSynthLayersOutboundUUIDForwarded(t *testing.T) {
	const src = `
outbounds:
  - name: up
    type: vmess
    server: 1.2.3.4:443
    uuid: 550e8400-e29b-41d4-a716-446655440000
    security: auto
`
	var f File
	if err := yaml.Unmarshal([]byte(src), &f); err != nil {
		t.Fatalf("解析: %v", err)
	}
	o := f.Outbounds[0]
	if o.UUID == "" {
		t.Fatal("uuid 应先落到具名字段 Outbound.UUID")
	}
	ls, err := o.synthLayers()
	if err != nil {
		t.Fatalf("synthLayers: %v", err)
	}
	for _, l := range ls {
		if l.Name == "vmess" {
			if got := l.Node.Get("uuid").Str(); got != "550e8400-e29b-41d4-a716-446655440000" {
				t.Fatalf("vmess 层 Node 应含 uuid,实为 %q", got)
			}
			if got := l.Node.Get("security").Str(); got != "auto" {
				t.Fatalf("协议标量字段 security 应保留,实为 %q", got)
			}
			return
		}
	}
	t.Fatal("未找到 vmess 层")
}
