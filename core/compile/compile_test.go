package compile_test

import (
	"context"
	"errors"
	"testing"

	"github.com/LOVECHEN/ntr/core/cap"
	"github.com/LOVECHEN/ntr/core/compile"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

type noCfg struct{}

// desc 用 registry.Make 造一个不注册的擦除描述符,喂给 compile.Order。
func desc(name string, band registry.Band, in []registry.Sort, out registry.Sort, req, adj, prov []cap.ID) registry.AnyDescriptor {
	return registry.Make(registry.Descriptor[noCfg]{
		Name: name, Band: band, In: in, Out: out,
		Requires: req, RequiresAdjacent: adj, Provides: prov,
		Parse: func(*spec.Node) (noCfg, error) { return noCfg{}, nil },
		Build: func(context.Context, noCfg, any) (any, error) { return nil, nil },
	})
}

var (
	tcp       = desc("tcp", registry.BandBase, nil, registry.SortStream, nil, nil, nil)
	tls       = desc("tls", registry.BandCrypto, []registry.Sort{registry.SortStream}, registry.SortStream, nil, nil, []cap.ID{cap.IDTLSExporter})
	reality   = desc("reality", registry.BandCrypto, []registry.Sort{registry.SortStream}, registry.SortStream, nil, nil, []cap.ID{cap.IDTLSExporter, cap.IDVisionCarrier})
	ws        = desc("ws", registry.BandFrame, []registry.Sort{registry.SortStream}, registry.SortStream, nil, nil, nil)
	vision    = desc("vision", registry.BandFlow, []registry.Sort{registry.SortStream}, registry.SortStream, nil, []cap.ID{cap.IDVisionCarrier}, nil)
	shadowtls = desc("shadowtls", registry.BandCryptoObfs, []registry.Sort{registry.SortStream}, registry.SortStream, []cap.ID{cap.IDTLSExporter}, nil, nil)
	vless     = desc("vless", registry.BandProxy, []registry.Sort{registry.SortStream}, registry.SortStream, nil, nil, nil)
)

// 书写顺序打乱,仍应按 Band 排成 tcp→tls→ws→vless。
func TestBandOrderingDeterministic(t *testing.T) {
	got, err := compile.Order([]registry.AnyDescriptor{ws, vless, tcp, tls})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tcp", "tls", "ws", "vless"}
	for i, d := range got {
		if d.Name() != want[i] {
			t.Fatalf("order[%d] = %q, want %q (full: %v)", i, d.Name(), want[i], names(got))
		}
	}
}

// 同 Band 两层(tls + reality 都 Band 20)→ E-BAND-CONFLICT。
func TestSameBandConflict(t *testing.T) {
	_, err := compile.Order([]registry.AnyDescriptor{tcp, tls, reality, vless})
	if !errors.Is(err, compile.ErrBandConflict) {
		t.Fatalf("err = %v, want ErrBandConflict", err)
	}
}

// vision 紧邻下层必须提供 VisionCarrier;中间夹了 ws → E-CAP-ADJACENCY。
func TestVisionAdjacencyBrokenByWS(t *testing.T) {
	// tcp → reality(Band20, provides VisionCarrier) → ws(Band30) → vision(Band40) → vless(Band60)
	// vision 紧邻下层是 ws(不提供 VisionCarrier)→ 报错。
	_, err := compile.Order([]registry.AnyDescriptor{tcp, reality, ws, vision, vless})
	if !errors.Is(err, compile.ErrCapAdjacency) {
		t.Fatalf("err = %v, want ErrCapAdjacency", err)
	}
}

// vision 直接骑在 reality 上(紧邻)→ 通过。
func TestVisionAdjacencyOK(t *testing.T) {
	got, err := compile.Order([]registry.AnyDescriptor{tcp, reality, vision, vless})
	if err != nil {
		t.Fatalf("unexpected err: %v (order %v)", err, names(got))
	}
}

// shadowtls Requires TLSExporter,但栈里没有真 TLS 层 → E-CAP-MISSING。
func TestRequiresMissing(t *testing.T) {
	_, err := compile.Order([]registry.AnyDescriptor{tcp, shadowtls, vless})
	if !errors.Is(err, compile.ErrCapMissing) {
		t.Fatalf("err = %v, want ErrCapMissing", err)
	}
}

func TestEmptyStack(t *testing.T) {
	if _, err := compile.Order(nil); !errors.Is(err, compile.ErrEmptyStack) {
		t.Fatalf("err = %v, want ErrEmptyStack", err)
	}
}

func names(ds []registry.AnyDescriptor) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Name()
	}
	return out
}
