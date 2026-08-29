package registry_test

import (
	"context"
	"testing"

	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

type demoCfg struct{ UUID string }

func demoDesc(name string) registry.Descriptor[demoCfg] {
	return registry.Descriptor[demoCfg]{
		Name: name,
		Band: registry.BandProxy,
		Out:  registry.SortStream,
		Parse: func(n *spec.Node) (demoCfg, error) {
			return demoCfg{UUID: n.Get("uuid").Str()}, nil
		},
		Build: func(_ context.Context, c demoCfg, _ any) (any, error) {
			return "built:" + c.UUID, nil
		},
	}
}

func TestRegisterLookupErased(t *testing.T) {
	registry.Register(demoDesc("demo-proto"))

	d, ok := registry.Lookup("demo-proto")
	if !ok {
		t.Fatal("registered descriptor not found")
	}
	if d.Band() != registry.BandProxy || d.Out() != registry.SortStream {
		t.Fatalf("erased band=%d out=%d", d.Band(), d.Out())
	}

	// 经擦除视图 Parse → Build,C 被折进闭包、断言回来喂强类型 Build。
	node := &spec.Node{Kind: spec.KindMap, Map: map[string]*spec.Node{"uuid": spec.Scalar("abc")}}
	cfgAny, err := d.Parse(node)
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Build(context.Background(), cfgAny, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != "built:abc" {
		t.Fatalf("Build returned %v, want built:abc", out)
	}
}

func TestDuplicateRegisterPanics(t *testing.T) {
	registry.Register(demoDesc("dup-proto"))
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate Register")
		}
	}()
	registry.Register(demoDesc("dup-proto"))
}

func TestLookupMissing(t *testing.T) {
	if _, ok := registry.Lookup("nope-proto"); ok {
		t.Fatal("found an unregistered descriptor")
	}
}
