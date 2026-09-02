package config

import (
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// TestKeySpecStructured:keys.<proto> 三形态解析 —— 标量、块式映射(复合键)、块式映射列表(复合轮换)。
func TestKeySpecStructured(t *testing.T) {
	const src = `
name: alice
keys:
  vless: 550e8400-e29b-41d4-a716-446655440000
  tuic:
    uuid: 11111111-1111-1111-1111-111111111111
    password: pw
  ssh:
    - {username: u1, password: p1}
    - {username: u2, password: p2}
`
	var u User
	if err := yaml.Unmarshal([]byte(src), &u); err != nil {
		t.Fatalf("解析: %v", err)
	}
	if v := u.Keys["vless"]; len(v.Values) != 1 || v.Values[0] == "" || len(v.Maps) != 0 {
		t.Fatalf("vless 应为标量: %+v", v)
	}
	tk := u.Keys["tuic"]
	if len(tk.Maps) != 1 || tk.Maps[0]["uuid"] == "" || tk.Maps[0]["password"] != "pw" {
		t.Fatalf("tuic 应为单组复合键: %+v", tk)
	}
	sk := u.Keys["ssh"]
	if len(sk.Maps) != 2 || sk.Maps[1]["username"] != "u2" {
		t.Fatalf("ssh 应为复合键轮换 2 组: %+v", sk)
	}
}

// TestDesugarStructuredKeys:复合键脱糖成带 Fields 的 AuthLayer;E-KEY-DUP 对复合键按规范化字段判重。
func TestDesugarStructuredKeys(t *testing.T) {
	users := []User{{
		Name: "alice",
		Keys: map[string]KeySpec{
			"tuic": {Maps: []map[string]string{{"uuid": "u-alice", "password": "pw-a"}}},
		},
	}}
	inbounds := map[string]bool{"tuic-in": true}
	stack := map[string][]string{"tuic-in": {"tuic"}}
	binds, err := Desugar(users, inbounds, stack)
	if err != nil {
		t.Fatalf("Desugar: %v", err)
	}
	if len(binds) != 1 {
		t.Fatalf("应产 1 条 binding,实为 %d", len(binds))
	}
	b := binds[0]
	if b.BillID != "alice@tuic-in" || len(b.Layers) != 1 {
		t.Fatalf("binding 错: %+v", b)
	}
	l := b.Layers[0]
	if l.Scheme != "tuic" || l.Key != nil || l.Fields["uuid"] != "u-alice" || l.Fields["password"] != "pw-a" {
		t.Fatalf("复合键层应带 Fields、Key 为 nil: %+v", l)
	}

	// E-KEY-DUP:两人同口同协议同一组复合字段 → 判死。
	dup := []User{
		{Name: "a", Keys: map[string]KeySpec{"tuic": {Maps: []map[string]string{{"uuid": "x", "password": "y"}}}}},
		{Name: "b", Keys: map[string]KeySpec{"tuic": {Maps: []map[string]string{{"uuid": "x", "password": "y"}}}}},
	}
	if _, err := Desugar(dup, inbounds, stack); err == nil {
		t.Fatal("复合键撞键应判 E-KEY-DUP")
	}
}
