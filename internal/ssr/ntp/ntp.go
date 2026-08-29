// Package ntp 是 vendored SSR 代码对 mihomo ntp 的最小替身。tls1.2_ticket_auth obfs
// 用它取当前时间填时间戳字段。NTR 不跑 NTP 校时,直接用系统时间即可(与线格式无关,
// 服务端对时间戳容忍窗口宽)。
package ntp

import "time"

// Now 返回系统当前时间(mihomo 版会用 NTP offset 校正,这里直接系统时间)。
func Now() time.Time { return time.Now() }
