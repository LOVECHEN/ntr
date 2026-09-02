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
// 当前只有配置文件路径写 OriginConfig;面板 credential 级 API(OriginAPI)尚未接入,
// 保留枚举是为 §4.9 的注册表消歧留位,不是已实现能力。
type Origin uint8

const (
	OriginConfig Origin = iota // 配置文件:顶层 users 块 / 口内凭据,经 reload 写入
	OriginAPI                  // 面板 credential 级 API(PutCredential/SyncCredentials …)—— 未接入
)

// AuthLayer 是认证栈里的一层:一个 (scheme, key)。有序,外→内(index 0 = 最外层)。
//
//   - 单层协议口(vless / trojan …):len(Layers) == 1
//   - 多层口(shadowtls 外 + snell 内 …):len(Layers) == 2;3 层同理往下加
//
// Scheme 直接用协议/传输插件的【注册名】(vless / shadowtls / snell …),与现有
// core/proxy.Authenticator.Auth 的 scheme 同源。Key 在脱糖阶段是【原始 secret 字节】;
// canonical 鉴权键(CredentialCodec.AuthKey 的产物)在装配期、拿到该协议实例后才派生 ——
// Desugar 不认识任何协议,派生不在它手里。
type AuthLayer struct {
	Scheme string // 协议/传输插件注册名(= Authenticator.Auth 的 scheme)
	Key    []byte // 脱糖期 = 原始 secret;装配期经 CredentialCodec.AuthKey 派生成鉴权键
}

// CredBinding 是一条脱糖产物:(inbound, 有序 auth 层) → 计费槽。脱糖的原子单位。
//
// 稳定身份 = BillID = "<name>@<inbound>",不可配、不可覆盖(§4.4 规则 5):name 与
// inbound 各自全局唯一 → BillID 在配置源内天然单射。轮换密钥(某层多把 key)在同层
// 产多个平行 binding、共享同一 BillID(过渡期用量并入一处,不清零 —— owner 拍板 B)。
//
// Name 是审计标签(= user 名),核心透传不解释;当前仅随 binding 携带,`explain` 等
// 消费者尚未落地。口级 flow 不在此处 —— 它是口的层参数,已随 synthStack 进协议 Node。
type CredBinding struct {
	Inbound string      // 口名
	Layers  []AuthLayer // 有序(外→内);多层须全部解析到同一 principal 才命中
	BillID  string      // 稳定身份 = "<name>@<inbound>"
	Name    string      // 审计标签(= user 名);核心透传不解释
	Limit   *LimitRef   // 该 user 共享的瞬时限流单元;nil = 无 user 级限制
	Origin  Origin
}

// LimitRef 是匿名【瞬时】限流单元(承 §4.5.1):一个 user 全部凭据共指一个。
// 它只承载瞬时状态、零持久化、重启归零 —— 【不是】User、【不是】被删除的 govCell:
// 无 quota / expire / consumed 累积态,不进计量树、不进 QueryStats、不进上报。
// 就是"限速 + 数连接 + 数 IP"三件瞬时事的合体(护栏见 §4.10#7:不得再加累积字段)。
//
// 装配期转成 meter.Limits 挂到该 user 各 BillID 的计量 cell 上;IP 超限动作当前仅 reject
// (evict-oldest 未实现,配置里写了会在 Desugar 期报错,不静默)。
type LimitRef struct {
	Rate     uint64 // bytes/s(令牌桶单位,复用现有 parseRate:200mbps→25e6);0 = 不限
	MaxConns uint32 // 0 = 不限
	MaxIPs   uint32 // 0 = 不限
}

// BillIDOf 派生计费身份 = "<name>@<inbound>"(§4.4 规则 5,唯一构造入口)。
func BillIDOf(name, inbound string) string { return name + "@" + inbound }
