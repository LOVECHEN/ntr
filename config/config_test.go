package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/LOVECHEN/ntr/core/spec"

	_ "github.com/LOVECHEN/ntr/manifest" // 注册协议供 Build 查表
)

const testUUID = "11111111-1111-1111-1111-111111111111"

// TestLoadMalformedYAML:坏 YAML 应返回错误,不 panic。
func TestLoadMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(p, []byte("inbounds: [ this is : not : valid : yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("坏 YAML 应报错")
	}
}

// TestBuildValid:合法 [vless] 裸栈入站 + direct 出站 → 建出 1 个实例。
func TestBuildValid(t *testing.T) {
	f := &File{
		Inbounds: []Inbound{{
			Name:     "in",
			Listen:   "127.0.0.1:0",
			Type:     "vless",
			Users:    []map[string]any{{"uuid": testUUID}},
			Outbound: "direct",
		}},
		Outbounds: []Outbound{{Name: "direct", Type: "direct"}},
	}
	insts, err := f.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(insts) != 1 {
		t.Fatalf("实例数 = %d, want 1", len(insts))
	}
}

// TestBuildErrors:各类畸形配置都应返回清晰错误(不 panic)。
func TestBuildErrors(t *testing.T) {
	cases := []struct {
		name string
		f    *File
	}{
		{"空 inbounds", &File{Outbounds: []Outbound{{Name: "direct", Type: "direct"}}}},
		{"入站缺 listen", &File{
			Inbounds:  []Inbound{{Name: "in", Type: "vless"}},
			Outbounds: []Outbound{{Name: "direct", Type: "direct"}},
		}},
		{"未知出站 type", &File{
			Inbounds:  []Inbound{{Name: "in", Listen: "127.0.0.1:0", Type: "vless"}},
			Outbounds: []Outbound{{Name: "x", Type: "no-such-outbound"}},
		}},
		{"未知层 type", &File{
			Inbounds:  []Inbound{{Name: "in", Listen: "127.0.0.1:0", Type: "no-such-layer", Outbound: "direct"}},
			Outbounds: []Outbound{{Name: "direct", Type: "direct"}},
		}},
		{"引用未定义出站", &File{
			Inbounds:  []Inbound{{Name: "in", Listen: "127.0.0.1:0", Type: "vless", Outbound: "ghost"}},
			Outbounds: []Outbound{{Name: "direct", Type: "direct"}},
		}},
		{"出站缺 name", &File{
			Inbounds:  []Inbound{{Name: "in", Listen: "127.0.0.1:0", Type: "vless", Outbound: "direct"}},
			Outbounds: []Outbound{{Type: "direct"}},
		}},
	}
	for _, c := range cases {
		if _, err := c.f.Build(context.Background()); err == nil {
			t.Errorf("%s:期望报错,却成功", c.name)
		}
	}
}

// TestBuildNonStringYAMLValues:YAML 里字段类型写错(uuid 是数字)不得 panic —— comma-ok 断言
// 应把它当空处理(该用户不注册),Build 仍成功。
func TestBuildNonStringYAMLValues(t *testing.T) {
	f := &File{
		Inbounds: []Inbound{{
			Name:     "in",
			Listen:   "127.0.0.1:0",
			Type:     "vless",
			Users:    []map[string]any{{"uuid": 12345}}, // 非字符串
			Outbound: "direct",
		}},
		Outbounds: []Outbound{{Name: "direct", Type: "direct"}},
	}
	insts, err := f.Build(context.Background()) // 不得 panic
	if err != nil {
		t.Fatalf("非字符串值不应导致 Build 失败:%v", err)
	}
	if len(insts) != 1 {
		t.Fatalf("实例数 = %d", len(insts))
	}
}

// TestValueToNode:任意 YAML 值(嵌套 map/序列/nil/数字/未知类型)转 Node 树,不 panic、类型正确。
func TestValueToNode(t *testing.T) {
	v := map[string]any{
		"s":      "str",
		"n":      42,
		"b":      true,
		"nil":    nil,
		"nested": map[string]any{"inner": 7},
		"seq":    []any{"a", 2, false},
		"weird":  struct{ X int }{1}, // 未知类型走 fmt.Sprint 兜底
	}
	node := valueToNode(v)
	if node.Kind != spec.KindMap {
		t.Fatalf("顶层应为 Map,得 %d", node.Kind)
	}
	if node.Map["s"].Str() != "str" {
		t.Errorf("s = %q", node.Map["s"].Str())
	}
	if node.Map["n"].Int(0) != 42 {
		t.Errorf("n = %d", node.Map["n"].Int(0))
	}
	if node.Map["nested"].Kind != spec.KindMap || node.Map["nested"].Map["inner"].Int(0) != 7 {
		t.Errorf("nested 解析错")
	}
	if node.Map["seq"].Kind != spec.KindSeq || len(node.Map["seq"].Seq) != 3 {
		t.Errorf("seq 解析错")
	}
	if node.Map["nil"].Kind != spec.KindNull {
		t.Errorf("nil 应为 Null")
	}
	if node.Map["weird"].Str() == "" {
		t.Errorf("未知类型应 fmt.Sprint 兜底为非空标量")
	}
}

// TestMapToNodeMissingFile:xxx-file 指向不存在的文件应报错,不 panic。
func TestMapToNodeMissingFile(t *testing.T) {
	if _, err := mapToNode(map[string]any{"cert-file": "/no/such/path/xyz.pem"}, "type"); err == nil {
		t.Fatal("缺文件应报错")
	}
}
