// Package spec 定义 Decode 产物 —— 哑的、无逻辑、无 I/O 的配置节点树。
//
// Descriptor.Parse 从 spec.Node 解析出协议自有的强类型 config(承设计第 4 章:
// Decode 阶段"哑,无逻辑",真正的 YAML 解码在 config 层填充 Node 树)。核心只认
// Node,不认任何具体协议的字段。
package spec

import "strconv"

// Kind 是节点种类。
type Kind uint8

const (
	KindNull Kind = iota
	KindScalar
	KindMap
	KindSeq
)

// Node 是一个哑配置节点(标量 / 映射 / 序列)。
type Node struct {
	Kind   Kind
	Scalar string
	Map    map[string]*Node
	Seq    []*Node
}

// Scalar 构造标量节点。
func Scalar(s string) *Node { return &Node{Kind: KindScalar, Scalar: s} }

// Get 返回映射子节点(不存在返回 nil)。
func (n *Node) Get(key string) *Node {
	if n == nil || n.Kind != KindMap {
		return nil
	}
	return n.Map[key]
}

// Str 返回标量字符串(非标量返回空串)。
func (n *Node) Str() string {
	if n == nil || n.Kind != KindScalar {
		return ""
	}
	return n.Scalar
}

// Int 解析标量为 int(失败返回 def)。
func (n *Node) Int(def int) int {
	if n == nil || n.Kind != KindScalar {
		return def
	}
	v, err := strconv.Atoi(n.Scalar)
	if err != nil {
		return def
	}
	return v
}

// Bool 解析标量为 bool。
func (n *Node) Bool() bool {
	if n == nil || n.Kind != KindScalar {
		return false
	}
	b, _ := strconv.ParseBool(n.Scalar)
	return b
}
