package config

import (
	"fmt"

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

// KeySpec 是 keys 下一个条目的值,两种【全块式】形态(无行内花括号):
//
//	单层单值:  vless: 550e8400-...          → Values=[uuid]
//	单层轮换:  vless:                        → Values=[uuid1,uuid2](零断连过渡,§4.8.1)
//	             - uuid1
//	             - uuid2
//
// 键 = 协议名(§4.4 规则 1:密钥属于"人×协议",一个协议一把)。多层口(如 shadowtls+snell)
// 消费该 user 的多把平铺密钥(keys.shadowtls + keys.snell),由【口的栈】按栈序(外→内)
// 自动取(§4.4 规则 3),绝不在 keys 里嵌套 —— 密钥怎么写 ⊥ 密钥被谁用。config 层不认识
// 任何协议名,键交给对应插件认领、scheme 由插件 Descriptor 自报,核心零 switch。
type KeySpec struct {
	Values []string // 标量→len 1;块式列表(轮换)→多值
}

// UnmarshalYAML 接受标量(单值)或块式序列(轮换列表)。映射(多层嵌套)已废 —— 多层组合
// 由口的栈表达、用 on 控制访问,不在 keys 里嵌套。
func (k *KeySpec) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		k.Values = []string{node.Value}
	case yaml.SequenceNode:
		if err := node.Decode(&k.Values); err != nil {
			return err
		}
	default:
		return fmt.Errorf("config: keys 的值须为标量或块式列表(轮换);多层组合由口的栈决定、用 on 控制,不在 keys 里嵌套")
	}
	return nil
}
