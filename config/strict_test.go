package config

import (
	"context"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"

	"github.com/LOVECHEN/ntr/service"
)

// 这组用例覆盖审计要求的「绝不静默」严格化(冻结律#6):所有会让层/凭据/限额静默失效的写法都必须判死。

func mustParse(t *testing.T, src string) File {
	t.Helper()
	var f File
	if err := yaml.Unmarshal([]byte(src), &f); err != nil {
		t.Fatalf("解析: %v", err)
	}
	return f
}

func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), sub) {
		t.Fatalf("应报含 %q 的错,实为: %v", sub, err)
	}
}

// 值形状分拣:与层同名的【标量】是终端协议字段(如 ssr 的 obfs: plain / protocol: origin),不误判成层;
// 只有【映射】值 + 注册层名才成层(simple-obfs 是 obfs: {mode,host})。
func TestSynthStrict_ScalarSharingLayerNameIsProtoField(t *testing.T) {
	f := mustParse(t, `
inbounds:
  - name: ssr-in
    type: ssr
    listen: 127.0.0.1:18080
    cipher: aes-256-cfb
    password: pw
    protocol: origin
    obfs: plain
    outbound: direct
`)
	ls, err := f.Inbounds[0].synthLayers()
	if err != nil {
		t.Fatalf("ssr 的 obfs: plain(标量)应作协议字段,不应报层错: %v", err)
	}
	for _, l := range ls {
		if l.Name == "obfs" {
			t.Fatal("obfs: plain 标量被误判成 simple-obfs 层")
		}
	}
	// 终端 ssr 层的节点应含 obfs/protocol 协议字段
	var ssr *service.LayerSpec
	for i := range ls {
		if ls[i].Name == "ssr" {
			ssr = &ls[i]
		}
	}
	if ssr == nil {
		t.Fatal("未找到 ssr 终端层")
	}
	if got := ssr.Node.Get("obfs").Str(); got != "plain" {
		t.Fatalf("ssr 节点应含 obfs=plain,实为 %q", got)
	}
}

// 映射值却不是注册层(拼错的 relaity:)→ 判死,不静默吞成协议字段。
func TestSynthStrict_UnknownLayerBlock(t *testing.T) {
	f := mustParse(t, `
inbounds:
  - name: v
    type: vless
    port: 1
    relaity:
      dest: x:443
`)
	_, err := f.Inbounds[0].synthLayers()
	wantErr(t, err, "未知层块")
}

// 旧 type: proxy + layers 数组已废除(第4章:type 直接写协议名)→ 判死。
func TestSynthStrict_LegacyProxyLayersRejected(t *testing.T) {
	f := mustParse(t, `
inbounds:
  - listen: 0.0.0.0:1
    type: proxy
    layers:
      - type: vless
`)
	_, err := f.Inbounds[0].synthLayers()
	wantErr(t, err, "不是注册的终端协议")
}

// 两个 user 在同口同协议用同一把 key → 鉴权歧义/计费串号 → E-KEY-DUP。
func TestDesugarStrict_KeyDup(t *testing.T) {
	users := []User{
		{Name: "u1", Keys: map[string]KeySpec{"vless": {Values: []string{"same-uuid"}}}},
		{Name: "u2", Keys: map[string]KeySpec{"vless": {Values: []string{"same-uuid"}}}},
	}
	_, err := Desugar(users, map[string]bool{"v-in": true}, map[string][]string{"v-in": {"vless"}})
	wantErr(t, err, "E-KEY-DUP")
	// 同 key 不同口不撞(每口独立 auth 表)
	users2 := []User{
		{Name: "u1", On: NameList{"a-in"}, Keys: map[string]KeySpec{"vless": {Values: []string{"same-uuid"}}}},
		{Name: "u2", On: NameList{"b-in"}, Keys: map[string]KeySpec{"vless": {Values: []string{"same-uuid"}}}},
	}
	if _, err := Desugar(users2, map[string]bool{"a-in": true, "b-in": true}, map[string][]string{"a-in": {"vless"}, "b-in": {"vless"}}); err != nil {
		t.Fatalf("不同口同 key 不应报错: %v", err)
	}
}

// on 含 all 又列具名口 → 判死;off 用保留字 all → 判死(明确报错而不是"未知口 all")。
func TestDesugarStrict_AllSemantics(t *testing.T) {
	ib := map[string]bool{"x": true}
	_, err := Desugar([]User{{Name: "a", On: NameList{"all", "x"}}}, ib, nil)
	wantErr(t, err, "all")
	_, err = Desugar([]User{{Name: "b", Off: NameList{"all"}}}, ib, nil)
	wantErr(t, err, "off 不支持保留字 all")
}

// 配了 per-user 限额但没开 metrics → 限额会静默失效 → Build 判死。
func TestBuildStrict_LimitsRequireMetrics(t *testing.T) {
	f := mustParse(t, `
inbounds:
  - name: v-in
    type: vless
    port: 10
users:
  - name: alice
    rate: 10mbps
    keys:
      vless: 550e8400-e29b-41d4-a716-446655440000
`)
	_, err := f.Build(context.Background())
	wantErr(t, err, "metrics")
}

// 流式出站把 sni/insecure 写在顶层(只被会话式出站消费)→ 会被静默忽略 → Build 判死。
func TestBuildStrict_OutboundTopLevelSNI(t *testing.T) {
	f := mustParse(t, `
inbounds:
  - name: m
    type: mixed
    listen: 127.0.0.1
    port: 11
outbounds:
  - name: up
    type: vless
    server: h:443
    secret: 550e8400-e29b-41d4-a716-446655440000
    sni: fake.example
`)
	_, err := f.Build(context.Background())
	wantErr(t, err, "tls: 层块")
}
