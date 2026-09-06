package service

import (
	"sync/atomic"
	"time"
)

// reaper 生命周期脊柱(承设计 §10)的默认超时:零配置即安全,config 的 lifecycle: 块可逐项覆盖。
// 这些默认覆盖四条生命周期漏洞的兜底期限;各 seam 的 <=0 入参一律回落到这里。
const (
	// DefaultHandshakeTimeout 握手统一 deadline(Seam 1):裸流上首字节前的最长等待,防 slow-loris。
	DefaultHandshakeTimeout = 10 * time.Second
	// DefaultTCPIdle 已计量 TCP 连接的滑动 idle(Seam 3,计量侧时间驱动 sweep;复用 lastActive)。
	DefaultTCPIdle = 300 * time.Second
	// DefaultUDPIdle UDP assoc 整关 idle(Seam 4):客户端静默超此则拆整条 assoc。
	DefaultUDPIdle = 60 * time.Second
	// DefaultHalfCloseIdle 半关后反向仍活时的尾部 idle(Seam 2):一端 FIN 后另一端静默的回收期限。
	DefaultHalfCloseIdle = 30 * time.Second
	// tcpKeepAlivePeriod 裸 TCP keepalive 探测周期:未计量明文 splice 连接的死连接兜底(见 serveConn)。
	tcpKeepAlivePeriod = 60 * time.Second
)

// udpIdleNanos 是 UDP assoc 整关 idle 的进程级取值(Seam 4;一进程一配置,reload 用 atomic 安全改)。
// 0 = 未设 → udpIdleTimeout() 回落 DefaultUDPIdle。udpNAT 主循环每次 ReadPacket 前据此 arm client deadline。
var udpIdleNanos atomic.Int64

// SetUDPIdle 由 config 在 Build 时设置 UDP assoc idle(≤0 = 回落默认)。reload 幂等。
func SetUDPIdle(d time.Duration) { udpIdleNanos.Store(int64(d)) }

// udpIdleTimeout 读当前 UDP assoc idle(未设 → 默认)。
func udpIdleTimeout() time.Duration {
	if v := udpIdleNanos.Load(); v > 0 {
		return time.Duration(v)
	}
	return DefaultUDPIdle
}
