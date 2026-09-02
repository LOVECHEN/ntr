// Package principal 是配置/面板脱糖的产物层(承设计第 4 章 §4.5)。
//
// 书写侧有两种糖:顶层 users 集中式(一人一块、keys 按协议)、或口内直接多凭据;
// 两种都由 Desugar 纯函数脱糖成同一种运行时装配单元 —— CredBinding。
// 「运行时无 user 对象」:User/口内凭据脱糖后蒸发,核心能指的最高对象是 CredBinding
// (≈一条凭据),外加可选共指的匿名 LimitRef。
//
// 本包只有哑类型 + 纯构造,无 I/O、无 wiring —— 与 core/cred(归属身份)对接:
// 一条 CredBinding 装配时对其每层 auth.Add(Scheme, Key, cred.Ref),多层须全部
// 解析到【同一】principal 才算命中该凭据,否则计入 cred.Unmatched。
package principal

// Origin 标记凭据的写者,供运行时注册表按来源消歧(承 §4.9:两个写者一张注册表)。
type Origin uint8

const (
	OriginConfig Origin = iota // 配置文件:顶层 users 块 / 口内凭据,经 reload 写入
	OriginAPI                  // 面板 credential 级 API(PutCredential/SyncCredentials …)
)

// AuthLayer 是认证栈里的一层:一个 (scheme, key)。有序,外→内(index 0 = 最外层)。
//
//   - 单层协议口(vless / trojan …):len(Layers) == 1
//   - 多层口(shadowtls 外 + snell 内 …):len(Layers) == 2;3 层同理往下加
//
// Scheme 直接用协议/传输插件的【注册名】(vless / shadowtls / snell …),与现有
// core/proxy.Authenticator.Auth 的 scheme 同源;Key 是 canonical 鉴权键,即插件
// CredentialCodec.AuthKey(secret) 的产物(客户端出示的 key 可与此不同,如 Trojan)。
// config 层【不认识】任何协议名 —— 每层由哪个插件认领、scheme 叫什么,靠 Desugar
// 走口的栈 + 插件 Descriptor 自报判定,核心零 switch。
type AuthLayer struct {
	Scheme string // 协议/传输插件注册名(= Authenticator.Auth 的 scheme)
	Key    []byte // canonical 鉴权键(= CredentialCodec.AuthKey 产物)
}

// CredBinding 是一条脱糖产物:(inbound, 有序 auth 层) → 计费槽。脱糖的原子单位。
//
// 稳定身份 = BillID = "<name>@<inbound>",不可配、不可覆盖(§4.4 规则 5):name 与
// inbound 各自全局唯一 → BillID 在配置源内天然单射。轮换密钥(某层多把 key)在同层
// 产多个平行 binding、共享同一 BillID(过渡期用量并入一处,不清零 —— owner 拍板 B)。
type CredBinding struct {
	Inbound string      // 口名
	Layers  []AuthLayer // 有序(外→内);多层须全部解析到同一 principal 才命中
	Flow    string      // 口级 flow(从 inbound 取,非 user 字段)
	BillID  string      // 稳定身份 = "<name>@<inbound>"
	Name    string      // 审计标签(= user 名 / 口内凭据名);核心透传不解释
	Limit   *LimitRef   // 该 user 共享的瞬时限流单元;nil = 无 user 级限制
	Origin  Origin
}

// IPExceedAction 是 user 级 IP 数触顶动作。
type IPExceedAction uint8

const (
	IPReject      IPExceedAction = iota // 拒新 IP(默认)
	IPEvictOldest                       // 踢最久未活动 IP —— "绝不断健康连接"的显式例外之一
)

// LimitRef 是匿名【瞬时】限流单元(承 §4.5.1):一个 user 全部凭据共指一个。
// 它只承载瞬时状态、零持久化、重启归零 —— 【不是】User、【不是】被删除的 govCell:
// 无 quota / expire / consumed 累积态,不进计量树、不进 QueryStats、不进上报。
// 就是"限速 + 数连接 + 数 IP"三件瞬时事的合体。字段集冻结在这五项(护栏见 §4.10#7)。
type LimitRef struct {
	ID          uint32 // Desugar 给每个"设了限制的 user 块"分配的内部索引;非用户名、非对外身份
	Rate        uint64 // bytes/s(令牌桶单位,复用现有 parseRate:200mbps→25e6);0 = 不限
	MaxConns    uint32 // 0 = 不限
	MaxIPs      uint32 // 0 = 不限
	OnExceedIPs IPExceedAction
}

// BillIDOf 派生计费身份 = "<name>@<inbound>"(§4.4 规则 5,唯一构造入口)。
func BillIDOf(name, inbound string) string { return name + "@" + inbound }
