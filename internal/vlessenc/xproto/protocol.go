// Package protocol 是 vendored VLESS Encryption 对 xray common/protocol 的最小替身。
// 仅提供 HasAESGCMHardwareSupport(选 AES-GCM vs ChaCha20Poly1305);用 x/sys/cpu 检测,
// 与 xray(同样基于硬件 AES 指令)在同一机器上取值一致 —— 两端一致才不 AEAD 失配。
package protocol

import "golang.org/x/sys/cpu"

// HasAESGCMHardwareSupport 反映本机是否有硬件 AES-GCM 加速(AES-NI / ARMv8 Crypto)。
var HasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	cpu.S390X.HasAESGCM ||
	(cpu.PPC64.IsPOWER8 || cpu.PPC64.IsPOWER9)
