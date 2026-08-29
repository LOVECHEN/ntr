package link

import "testing"

type probe interface{ mark() int }

type leaf struct{ v int }

func (l *leaf) mark() int { return l.v }

type wrap struct{ below any }

func (w *wrap) Unwrap() any { return w.below }

func TestGetCapabilityFound(t *testing.T) {
	// 叶子实现 probe,外面套两层 wrap;GetCapability 应沿 Unwrap 链找到它。
	stack := &wrap{below: &wrap{below: &leaf{v: 42}}}
	p, ok := GetCapability[probe](stack)
	if !ok {
		t.Fatal("capability not found along Unwrap chain")
	}
	if got := p.mark(); got != 42 {
		t.Fatalf("mark() = %d, want 42", got)
	}
}

func TestGetCapabilityMissing(t *testing.T) {
	stack := &wrap{below: &wrap{below: &leaf{v: 1}}}
	type absent interface{ nope() }
	if _, ok := GetCapability[absent](stack); ok {
		t.Fatal("found a capability that no layer implements")
	}
}

func TestGetCapabilityTopLayer(t *testing.T) {
	// 顶层自己就实现 —— 立即命中,不必剥。
	l := &leaf{v: 7}
	p, ok := GetCapability[probe](l)
	if !ok || p.mark() != 7 {
		t.Fatalf("top-layer capability: ok=%v", ok)
	}
}
