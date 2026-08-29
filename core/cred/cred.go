// Package cred 定义归属身份类型(承设计第 2 章 §2.3)——核心里最小的归属单元,
// 不认识 user、quota、expire。计量树节点即开关树节点,一根 Node 指针三用。
package cred

import "net/netip"

// ID 是面板指定的稳定计费槽身份;核心只透传、不解释。
type ID uint64

const (
	// Unmatched 每 Service 保留:探测 / 伪装握手 / 鉴权失败连接的 pre-auth 残量归此。
	Unmatched ID = 0
	// Ambient 有门无选择(共享 PSK 服务)/ by-inbound / fixed 的兜底主体。
	Ambient ID = 1
	// UserBase 具名凭据从此起(面板分配),不撞保留字。
	UserBase ID = 1 << 20
)

// StopReason 是热开关 / 生命周期收尾的断因(承第 2 章 §2.3.2、第 10 章 §10.2、
// 第 12 章决策①的 A/B 分类)。
type StopReason uint8

const (
	ReasonUnknown StopReason = iota

	// A 类 · 行政性驱逐(断的是健康连接,恰四类,每类必计数 + 必日志;承第 6 章 §6.4ter)。
	ReasonDisable     // 面板热开关 Disable/Enable(credID)
	ReasonKillIP      // KillIP(cred,ip)
	ReasonKillConn    // KillConn(id)
	ReasonEvictOldest // user 级 on-exceed-ips: evict-oldest
	ReasonReloadDrain // reload Drain:删口 / 改拓扑
	ReasonMemGuard    // mem-guard hard 档

	// B 类 · 生命周期自然 / 超时终止(不算"断健康连接",不占 A 类名额)。
	ReasonEOF              // FIN/RST 正常关闭
	ReasonIdleTimeout      // TCP idle(第 12 章决策①:idle 归 B)
	ReasonHandshakeTimeout // 握手 / 接入 deadline
	ReasonSniffTimeout     // 嗅探超时
	ReasonHalfClose        // 半关后反向 idle 回收
	ReasonUDPIdle          // UDP assoc idle reap
	ReasonProbeTimeout     // 健康探测连接超时(第 11 章 §11.3.7)
	ReasonFetchTimeout     // 订阅 / geo / ruleset 拉取连接超时(第 11 章 §11.4.3)
	ReasonForceSettle      // reaper 对已判死单元的兜底收尾
	ReasonShutdown         // 优雅关闭
)

// Node 是计量树节点(= 开关树节点):一根指针三用(计量 / 热开关 / 瞬时限制)。
type Node interface {
	// Drain 每 T 字节泄流入账(计量;非每字节)。
	Drain(up, down uint64)
	// Cancel 热开关:cancel 挂在本节点子树下的全部活连接。
	Cancel(reason StopReason)
	// Admit 瞬时限制:接入时查 max-conns/max-ips 水位,超限即 false。
	Admit(src netip.Addr) bool
}

// Ref 是凭据归属句柄(只读):计量 / 热开关 / 瞬时限制三职责都锚在它。
// Node 是跨快照存活的稳定指针 —— 计量树节点 = 开关树节点。
type Ref struct {
	ID   ID
	Node Node
}
