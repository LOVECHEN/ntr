package service

import (
	"log"
	"os"
	"sync/atomic"
)

// debugEnabled 控制握手/处理错误的观测输出。默认由环境变量 NTR_DEBUG 决定(非空即开),cmd 也可
// 经 SetDebug 显式开关。默认关:入站握手/鉴权失败是常态(主动探测、错凭据),无条件打印会刷屏。
//
// 开后:每条失败连接打印源地址 + 错误。这是排查「跑不通」的关键 —— 尤其配置键写错被静默吞的坑
// (第9-10轮血泪:server-name 误写 sni → 握手期早返、错误被这里丢弃 → 表现成"连不上",极难查)。
var debugEnabled atomic.Bool

func init() {
	if os.Getenv("NTR_DEBUG") != "" {
		debugEnabled.Store(true)
	}
}

// SetDebug 开关握手错误观测(cmd 层可据 -debug flag 调用)。
func SetDebug(on bool) { debugEnabled.Store(on) }

// debugf 仅在 debug 开时打印(前缀 ntr-debug)。
func debugf(format string, args ...any) {
	if debugEnabled.Load() {
		log.Printf("ntr-debug: "+format, args...)
	}
}
