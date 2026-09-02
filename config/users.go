package config

import (
	"fmt"
	"sort"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// OnAll 是 on 的保留字:显式全开(该用户能连所有他有密钥的口)。
const OnAll = "all"

// NameList 是口名列表,接受【标量】(如 on: all)或【块式序列】两种全块式写法。
type NameList []string

// UnmarshalYAML 允许标量单值(如 on: all)或块式列表。
func (n *NameList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		*n = NameList{node.Value}
	case yaml.SequenceNode:
		var s []string
		if err := node.Decode(&s); err != nil {
			return err
		}
		*n = s
	default:
		return fmt.Errorf("config: on/off 须为标量(如 all)或块式列表")
	}
	return nil
}

// User 是配置文件里的一个用户块(第4章 §4.3.5,on 语义按 owner 调整为默认全开):
// 权限 + 密钥。它是【编译期糖】—— Desugar 把它展开成各口的 principal.CredBinding,
// 运行时不存在 User 对象(§4.5.3)。rate/max-conns/max-ips 作用于该用户【全部密钥合计】。
//
// 访问控制(on/off),口为粒度(每个口 = 一个精确协议栈/版本组合):
//   - 缺省 on(且缺省 off)      → 全开:能连所有他有密钥的口
//   - on: all                   → 保留字,显式全开(= 缺省)
//   - on: [口…]                 → 白名单收窄:只这些口
//   - off: [口…]                → 黑名单:从当前允许集屏蔽这些口
//
// on 与 off 可叠加:on:all + off:[x] = 除 x 外全开;on:[a,b] + off:[b] = 只 a。
// "能不能连某口"最终 = (口 ∈ 允许集) AND (该口栈所需密钥都在 keys 里) AND (未被面板 Disable)。
type User struct {
	Name        string             `yaml:"name"`
	On          NameList           `yaml:"on"`   // 白名单口名;标量 all 或块式列表;含 "all" 或缺省 = 全开
	Off         NameList           `yaml:"off"`  // 黑名单口名;从允许集屏蔽
	Keys        map[string]KeySpec `yaml:"keys"` // 键=协议名,值=该协议凭据(平铺;多层组合由口的栈决定)
	Rate        string             `yaml:"rate"` // 带宽串(如 200mbps);合计上限。Desugar 解析
	MaxConns    uint32             `yaml:"max-conns"`
	MaxIPs      uint32             `yaml:"max-ips"`
	OnExceedIPs string             `yaml:"on-exceed-ips"` // reject(默认);evict-oldest 未实现——写了 Desugar 期报错,不静默
}

// AllowsAllInbounds 报此用户是否"全开"(缺省 on 或 on 含保留字 all)。
// 全开语义下,允许集 = 所有口,再由 Off 黑名单挖除、由 keys 是否齐全过滤。
func (u User) AllowsAllInbounds() bool {
	if len(u.On) == 0 {
		return true
	}
	for _, o := range u.On {
		if o == OnAll {
			return true
		}
	}
	return false
}

// KeySpec 是 keys 下一个条目的值,三种【全块式】形态(无行内花括号):
//
//	标量单值:  vless: 550e8400-...          → Values=[uuid]
//	标量轮换:  vless:                        → Values=[uuid1,uuid2](零断连过渡,§4.8.1)
//	             - uuid1
//	             - uuid2
//	结构化(复合键,如 tuic uuid+password / ssh user+password):
//	           tuic:                          → Maps=[{uuid:...,password:...}]
//	             uuid: 550e8400-...
//	             password: pw
//	结构化轮换:tuic:                          → Maps=[{...},{...}]
//	             - {uuid: ..., password: ...}  # 块式:一个 - 一组
//
// 键 = 协议名(§4.4 规则 1:密钥属于"人×协议",一个协议一把;复合键 = 该协议的一组具名字段)。多层口
// (如 shadowtls+snell)消费该 user 的多把平铺密钥,由【口的栈】按栈序(外→内)自动取(§4.4 规则 3),
// 绝不在 keys 里嵌套【口名/层】—— 结构化形态是【单个协议凭据的具名字段】(uuid/password…),不是层嵌套。
// config 层不认识任何协议名,字段交给对应插件按需取,核心零 switch。
type KeySpec struct {
	Values []string            // 标量凭据:标量→len 1;块式列表(轮换)→多值
	Maps   []map[string]string // 结构化复合凭据:映射→len 1;块式映射列表(轮换)→多值
}

// UnmarshalYAML 接受标量(单值)、块式序列(标量轮换 或 结构化轮换)、映射(单个结构化复合键)。
func (k *KeySpec) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		k.Values = []string{node.Value}
	case yaml.MappingNode: // 结构化复合键(单组):tuic: {uuid, password}
		var m map[string]string
		if err := node.Decode(&m); err != nil {
			return err
		}
		k.Maps = []map[string]string{m}
	case yaml.SequenceNode: // 轮换:元素全为标量 → Values;全为映射 → Maps;混写报错
		if len(node.Content) == 0 {
			return nil
		}
		if node.Content[0].Kind == yaml.MappingNode {
			if err := node.Decode(&k.Maps); err != nil {
				return err
			}
		} else {
			if err := node.Decode(&k.Values); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("config: keys 的值须为标量、块式列表(轮换)或映射(复合键的具名字段);不在 keys 里嵌套口名/层")
	}
	return nil
}

// credValue 是一把 key 的值:标量(scalar)或结构化具名字段(fields,复合键)。Desugar 与装配期共用。
type credValue struct {
	scalar string
	fields map[string]string
}

// creds 把 KeySpec 展平成有序 credValue 列表(标量在前、结构化在后;通常一个 KeySpec 只用一种形态)。
func (k KeySpec) creds() []credValue {
	out := make([]credValue, 0, len(k.Values)+len(k.Maps))
	for _, v := range k.Values {
		out = append(out, credValue{scalar: v})
	}
	for _, m := range k.Maps {
		out = append(out, credValue{fields: m})
	}
	return out
}

// empty 报告该协议是否没配任何凭据。
func (k KeySpec) empty() bool { return len(k.Values) == 0 && len(k.Maps) == 0 }

// dupKey 是 credValue 的规范化去重键(E-KEY-DUP 用):标量原样;结构化按字段名排序拼 "k=v"。
func (c credValue) dupKey() string {
	if c.fields == nil {
		return c.scalar
	}
	ks := make([]string, 0, len(c.fields))
	for k := range c.fields {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	for _, k := range ks {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(c.fields[k])
		b.WriteByte('\x00')
	}
	return b.String()
}
