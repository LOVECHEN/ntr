// Package compile 把无序的层集编译成确定性的、经校验的变换器栈(承设计第 3 章 §3.2)。
//
// 层序完全由 Band 定,书写顺序不参与 —— 两份键序不同的等价配置产出逐字节相同的栈。
// 排完序后做三重邻接校验:形状邻接(下层 Out ∈ 本层 In)、Requires 可达(任意下层
// 提供)、RequiresAdjacent 紧邻(必须由紧邻下层直接提供,Vision 用)。任何非法组合
// 在编译期判死、大声报,绝不留到运行期静默直连。
package compile

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/LOVECHEN/ntr/core/cap"
	"github.com/LOVECHEN/ntr/core/registry"
)

// 编译期错误(对应设计里的 E-* 诊断)。
var (
	ErrEmptyStack     = errors.New("compile: empty stack")                                      // 空栈
	ErrBandConflict   = errors.New("compile: two layers occupy the same Band")                  // E-BAND-CONFLICT
	ErrShapeAdjacency = errors.New("compile: shape mismatch between adjacent layers")           // E-LAYER-ORDER
	ErrCapAdjacency   = errors.New("compile: RequiresAdjacent not provided by immediate lower") // E-CAP-ADJACENCY
	ErrCapMissing     = errors.New("compile: Requires not provided by any lower layer")         // E-CAP-MISSING
)

// Order 把一组层描述符按 Band 升序排成确定性栈(底→顶)并做邻接校验。
// 返回排好序的层(新切片,不改入参)。校验失败返回带上下文的 typed error。
func Order(layers []registry.AnyDescriptor) ([]registry.AnyDescriptor, error) {
	if len(layers) == 0 {
		return nil, ErrEmptyStack
	}

	sorted := make([]registry.AnyDescriptor, len(layers))
	copy(sorted, layers)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Band() < sorted[j].Band()
	})

	// 同 Band 冲突:糖表达里每个 band 至多 1 层(如同时写 tls 和 reality)。
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Band() == sorted[i-1].Band() {
			return nil, fmt.Errorf("%w: %q and %q both at Band %d",
				ErrBandConflict, sorted[i-1].Name(), sorted[i].Name(), sorted[i].Band())
		}
	}

	// 自底向上累积"下层已提供的能力",逐层校验。
	provided := make(map[cap.ID]bool)
	for i, layer := range sorted {
		var lower registry.AnyDescriptor
		if i > 0 {
			lower = sorted[i-1]
		}

		// 形状邻接:紧邻下层的 Out 必须是本层 In 之一(In 为空 = 底层,无约束)。
		if lower != nil && len(layer.In()) > 0 && !slices.Contains(layer.In(), lower.Out()) {
			return nil, fmt.Errorf("%w: %q(out=%d) → %q(in=%v)",
				ErrShapeAdjacency, lower.Name(), lower.Out(), layer.Name(), layer.In())
		}

		// RequiresAdjacent:必须由紧邻下层直接提供(比 Requires 的"可达"更严)。
		for _, id := range layer.RequiresAdjacent() {
			if lower == nil || !slices.Contains(lower.Provides(), id) {
				return nil, fmt.Errorf("%w: %q needs cap %d adjacently; lower %s provides %v",
					ErrCapAdjacency, layer.Name(), id, lowerName(lower), lowerProvides(lower))
			}
		}

		// Requires(可达):任意下层提供即可。
		for _, id := range layer.Requires() {
			if !provided[id] {
				return nil, fmt.Errorf("%w: %q needs cap %d, no lower layer provides it",
					ErrCapMissing, layer.Name(), id)
			}
		}

		for _, id := range layer.Provides() {
			provided[id] = true
		}
	}
	return sorted, nil
}

func lowerName(d registry.AnyDescriptor) string {
	if d == nil {
		return "(none)"
	}
	return d.Name()
}

func lowerProvides(d registry.AnyDescriptor) []cap.ID {
	if d == nil {
		return nil
	}
	return d.Provides()
}
