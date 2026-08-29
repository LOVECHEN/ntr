// Package log 是 vendored SSR 代码对 mihomo log 的最小替身。vendored 代码仅用 Warnln
// (auth_chain 的偶发告警),NTR 内置日志走别处,这里做成无操作即可(不影响协议行为)。
package log

// Warnln 无操作占位(与 mihomo 签名一致)。
func Warnln(format string, v ...any) {}
