// Package registry 定义强类型注册表 Descriptor[C] 与全局注册/查找(承设计第 2 章
// §2.5、第 3 章 §3.2)。核心侧只持一张 map[string]anyDescriptor 并遍历它,从不枚举
// kind —— "加协议核心零 diff"的类型层落点。协议在自己包的 init() 里 Register,
// 由 manifest/ 一行 blank-import 决定链接哪些。
package registry

import (
	"context"
	"fmt"
	"sync"

	"github.com/LOVECHEN/ntr/core/cap"
	"github.com/LOVECHEN/ntr/core/spec"
)

// Band 是规范层序位次;栈按此升序排列,书写顺序不参与(承第 3 章 §3.2.2)。
type Band uint8

const (
	BandBase       Band = 10 // tcp, udp
	BandCrypto     Band = 20 // tls, reality(互斥,同 band)
	BandCryptoObfs Band = 25 // shadowtls
	BandFrame      Band = 30 // ws, grpc, h2, httpupgrade, splithttp, mkcp
	BandFlow       Band = 40 // vision
	BandSession    Band = 50 // quic, muxcool, smux, yamux, h2mux
	BandProxy      Band = 60 // vless, vmess, trojan, ss, snell, socks, http, hysteria2
)

// Sort 是形状排序(形状邻接的类型层判据)。
type Sort uint8

const (
	SortStream Sort = iota
	SortPacket
	SortSession
	SortDevice
)

// ReloadClass 是热重载类别(承第 1 章 §1.4.5:一切皆热三档)。
type ReloadClass uint8

const (
	ReloadInPlace ReloadClass = iota // 零掉线
	ReloadDrain                      // 只影响该单元
	ReloadHard                       // 必断(TUN/WG 设备)
)

// Descriptor 是一个可注册的变换器 / 协议的声明式描述,C 是协议自有强类型 config。
type Descriptor[C any] struct {
	Name             string
	Display          string // 显示名自带,消灭中心 AdapterType.String() 枚举
	Band             Band
	In               []Sort // 各下层要求的 sort(形状邻接)
	Out              Sort   // 本节点产出的 sort(可迁移,如 QUIC: Packet→Session)
	Requires         []cap.ID
	RequiresAdjacent []cap.ID // 必须由【紧邻下层】直接提供(vision 用)
	Provides         []cap.ID
	Reload           ReloadClass
	Parse            func(*spec.Node) (C, error)
	Build            func(ctx context.Context, cfg C, below any) (any, error)
}

// AnyDescriptor 是去泛型的擦除视图 —— core/compile 只见这个,不见 C。
type AnyDescriptor interface {
	Name() string
	Display() string
	Band() Band
	In() []Sort
	Out() Sort
	Requires() []cap.ID
	RequiresAdjacent() []cap.ID
	Provides() []cap.ID
	Reload() ReloadClass
	Parse(*spec.Node) (any, error)
	Build(ctx context.Context, cfg any, below any) (any, error)
}

// erased 把 Descriptor[C] 擦成 AnyDescriptor(C 折进闭包)。
type erased struct {
	name             string
	display          string
	band             Band
	in               []Sort
	out              Sort
	requires         []cap.ID
	requiresAdjacent []cap.ID
	provides         []cap.ID
	reload           ReloadClass
	parse            func(*spec.Node) (any, error)
	build            func(ctx context.Context, cfg any, below any) (any, error)
}

func (e *erased) Name() string                    { return e.name }
func (e *erased) Display() string                 { return e.display }
func (e *erased) Band() Band                      { return e.band }
func (e *erased) In() []Sort                      { return e.in }
func (e *erased) Out() Sort                       { return e.out }
func (e *erased) Requires() []cap.ID              { return e.requires }
func (e *erased) RequiresAdjacent() []cap.ID      { return e.requiresAdjacent }
func (e *erased) Provides() []cap.ID              { return e.provides }
func (e *erased) Reload() ReloadClass             { return e.reload }
func (e *erased) Parse(n *spec.Node) (any, error) { return e.parse(n) }
func (e *erased) Build(ctx context.Context, cfg, below any) (any, error) {
	return e.build(ctx, cfg, below)
}

var reg = struct {
	mu sync.RWMutex
	m  map[string]AnyDescriptor
}{m: make(map[string]AnyDescriptor)}

// Make 把 Descriptor[C] 擦成 AnyDescriptor 但【不注册】——供 core/compile 与测试直接
// 构造擦除视图(不污染全局注册表)。Register 内部也走它。
func Make[C any](d Descriptor[C]) AnyDescriptor {
	if d.Name == "" || d.Parse == nil || d.Build == nil {
		panic("registry: Descriptor missing Name/Parse/Build")
	}
	return &erased{
		name: d.Name, display: d.Display, band: d.Band,
		in: d.In, out: d.Out,
		requires: d.Requires, requiresAdjacent: d.RequiresAdjacent, provides: d.Provides,
		reload: d.Reload,
		parse:  func(n *spec.Node) (any, error) { return d.Parse(n) },
		build: func(ctx context.Context, cfg any, below any) (any, error) {
			// cfg 是 Parse 返回、被擦成 any 的 C;断言回 C 喂给强类型 Build。
			c, ok := cfg.(C)
			if !ok {
				return nil, fmt.Errorf("registry: %q Build got config of wrong type %T", d.Name, cfg)
			}
			return d.Build(ctx, c, below)
		},
	}
}

// Register 注册一个 Descriptor[C]。协议包在 init() 里调用;重名 panic(配置期错误)。
func Register[C any](d Descriptor[C]) {
	e := Make(d)
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if _, dup := reg.m[e.Name()]; dup {
		panic(fmt.Sprintf("registry: duplicate descriptor %q", e.Name()))
	}
	reg.m[e.Name()] = e
}

// Lookup 按名查找已注册的 Descriptor(擦除视图)。
func Lookup(name string) (AnyDescriptor, bool) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	d, ok := reg.m[name]
	return d, ok
}

// Each 遍历所有已注册 Descriptor(compile 用)。
func Each(fn func(AnyDescriptor)) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	for _, d := range reg.m {
		fn(d)
	}
}

// Len 返回已注册数。
func Len() int {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return len(reg.m)
}
