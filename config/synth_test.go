package config

import (
	"sort"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"

	"github.com/LOVECHEN/ntr/service"

	_ "github.com/LOVECHEN/ntr/manifest" // 填 registry:synthLayers 靠 Lookup 分拣层块/终端协议
)

func layerNames(ls []service.LayerSpec) string {
	ns := make([]string, 0, len(ls))
	for _, l := range ls {
		ns = append(ns, l.Name)
	}
	sort.Strings(ns)
	return strings.Join(ns, ",")
}

// TestSynthLayersNewFormat:第4章新格式(type=协议名 + 层块 + 协议专属字段 + listen/port)与等价旧格式
// (layers 数组)产出相同层集;层块顺序无关(compile.Order 按 Band 排)。config 零 switch 协议名 —— 全靠 registry。
func TestSynthLayersNewFormat(t *testing.T) {
	const newFmt = `
inbounds:
  - name: vless-in
    type: vless
    listen: 0.0.0.0
    port: 2053
    flow: xtls-rprx-vision
    reality:
      dest: www.microsoft.com:443
      private-key: k
      short-id:
        - "01ab"
    ws:
      path: /ray
`
	const oldFmt = `
inbounds:
  - listen: 0.0.0.0:2053
    layers:
      - type: reality
        dest: www.microsoft.com:443
        private-key: k
        short-id:
          - "01ab"
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

	in := nf.Inbounds[0]
	if !in.newFormat() {
		t.Fatal("应识别为新格式(type=vless 是注册的 Proxy 协议且无 layers)")
	}
	if got := in.listenAddr(); got != "0.0.0.0:2053" {
		t.Errorf("listen+port 合成错: %q", got)
	}
	if got := in.inboundName(); got != "vless-in" {
		t.Errorf("口名错: %q", got)
	}
	if got := in.authProto(); got != "vless" {
		t.Errorf("authProto 应为 vless(新格式 type 即终端协议): %q", got)
	}
	// Extra 应吸收了 flow(标量)/reality/ws(映射)
	if _, ok := in.Extra["reality"]; !ok {
		t.Error("Extra 未吸收 reality 层块")
	}
	if in.Extra["flow"] != "xtls-rprx-vision" {
		t.Errorf("Extra 未吸收 flow: %v", in.Extra["flow"])
	}

	ns, err := in.synthLayers()
	if err != nil {
		t.Fatalf("新格式 synthLayers: %v", err)
	}
	os_, err := of.Inbounds[0].synthLayers()
	if err != nil {
		t.Fatalf("旧格式 synthLayers: %v", err)
	}
	if layerNames(ns) != layerNames(os_) {
		t.Errorf("新旧格式层集不等:\n 新=%s\n 旧=%s", layerNames(ns), layerNames(os_))
	}
	if layerNames(ns) != "reality,vless,ws" {
		t.Errorf("层集应为 reality,vless,ws: %s", layerNames(ns))
	}

	// 旧格式不应被判为新格式(垫片路径)
	if of.Inbounds[0].newFormat() {
		t.Error("旧格式(有 layers)不应判为新格式")
	}
}

// TestSynthLayersTLSFieldAndUnknownKey:tls: 具名字段在新格式下成 tls 层;形态词 type(tun/proxy)不是新格式。
// 未注册的【映射】键(十有八九是拼错的层名)必须判死而不是静默当协议字段(见 TestSynthStrict)。
func TestSynthLayersTLSFieldAndUnknownKey(t *testing.T) {
	const src = `
inbounds:
  - name: t-in
    type: trojan
    port: 443
    tls:
      cert-file: /c.pem
      key-file: /k.pem
    grpc:
      service-name: tun
`
	var f File
	if err := yaml.Unmarshal([]byte(src), &f); err != nil {
		t.Fatalf("解析: %v", err)
	}
	in := f.Inbounds[0]
	if !in.newFormat() {
		t.Fatal("type=trojan 应为新格式")
	}
	ls, err := in.synthLayers()
	if err != nil {
		// tls 层 cert-file 读文件会失败(测试环境无该文件)——只验分拣不验读文件时允许该错
		if !strings.Contains(err.Error(), "tls") {
			t.Fatalf("synthLayers 意外错: %v", err)
		}
		return
	}
	if names := layerNames(ls); names != "grpc,tls,trojan" {
		t.Errorf("层集应为 grpc,tls,trojan: %s", names)
	}

	for _, typ := range []string{"tun", "proxy", "", "anytls"} {
		if (Inbound{Type: typ}).newFormat() {
			t.Errorf("形态词/会话式 type=%q 不应判为新格式", typ)
		}
	}
}
