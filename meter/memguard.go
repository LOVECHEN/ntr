package meter

import (
	"context"
	"log"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

// MemGuard 是防 OOM 治理的第二、三道防线(承设计 §6.4bis;第一道 debug.SetMemoryLimit 由 config 在
// Build 期直接设,是运行时原生行为,不在此)。它周期采样当前内存占用,置一个「档位」原子:
//
//	normal          正常
//	soft(默认 80%) 拒新连接(admission 处查 AdmitOK;已建立连接一条不动 —— 守住「只拒新绝不踢老」)
//	hard(默认 92%) 踢「最久无数据传输」的连接,直到回落到 soft 以下(全章第三个、也是最后一个断已建
//	                立连接的机制:保住进程 > 保住个别连接,OOM 是全体一起死)
//
// 阈值以【config 声明的 limit】为基数(soft/hard 是其百分比)。判定读【进程 RSS】(OOM killer 看的是
// RSS,不是 Go heap;Linux 走 /proc/self/statm,其它平台回退 runtime.MemStats.Sys-HeapReleased)。
// 硬阈值踢连接依赖计量注册表里的活连接候选集 —— 计量关闭时踢无可踢(evictIdle 空操作),此时 hard 档
// 退化为「持续拒新」(仍安全)。
type MemGuard struct {
	reg        *Registry // 踢空闲连接的候选集来源(nil / 计量关 → 硬阈值只能拒新)
	softBytes  uint64    // ≥ 此值进 soft 档;0 = 不设
	hardBytes  uint64    // ≥ 此值进 hard 档;0 = 不设
	limitBytes uint64    // config 声明的内存预算(= SetMemoryLimit 的值;仅用于状态面展示)
	interval   time.Duration
	evictBatch int           // 每个 tick 最多踢多少条(退避:一 tick 一批,不在单 tick 疯踢,承 §6.4bis.4 注2)
	sample     func() uint64 // 当前内存占用采样器(默认 currentMemBytes;测试可注入)

	phase        atomic.Int32  // 当前档位(MemPhase)
	softRejected atomic.Uint64 // 因 soft 拒新的连接数(§6.4bis.2 必计数)
	hardEvicted  atomic.Uint64 // 因 hard 踢掉的连接数(§6.4bis.3 必计数)
	lastPhaseLog atomic.Int32  // 上次已记日志的档位(仅在档位跃迁时记一行,不刷屏)
}

// MemPhase 是内存治理档位。
type MemPhase int32

const (
	MemNormal MemPhase = iota
	MemSoft
	MemHard
)

func (p MemPhase) String() string {
	switch p {
	case MemSoft:
		return "soft"
	case MemHard:
		return "hard"
	default:
		return "normal"
	}
}

// NewMemGuard 建守卫。softBytes/hardBytes 已是绝对字节(config 由 limit×百分比 算好)。reg 供硬阈值踢
// 空闲连接(可 nil)。interval/evictBatch 取默认(500ms / 64)当传 0。
func NewMemGuard(reg *Registry, limitBytes, softBytes, hardBytes uint64, interval time.Duration, evictBatch int) *MemGuard {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	if evictBatch <= 0 {
		evictBatch = 64
	}
	return &MemGuard{
		reg: reg, limitBytes: limitBytes, softBytes: softBytes, hardBytes: hardBytes,
		interval: interval, evictBatch: evictBatch, sample: currentMemBytes,
	}
}

// AdmitOK 供 admission 处查询:soft/hard 档一律拒新(计数)。nil 守卫恒放行(零成本)。
func (g *MemGuard) AdmitOK() bool {
	if g == nil {
		return true
	}
	if MemPhase(g.phase.Load()) >= MemSoft {
		g.softRejected.Add(1)
		return false
	}
	return true
}

// Run 跑采样循环,阻塞至 ctx 取消(作为一个 Instance 由 config.Build 挂上)。
func (g *MemGuard) Run(ctx context.Context) error {
	t := time.NewTicker(g.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			g.tick()
		}
	}
}

// tick 采样一次并按档位动作。
func (g *MemGuard) tick() {
	cur := g.sample()
	switch {
	case g.hardBytes > 0 && cur >= g.hardBytes:
		g.setPhase(MemHard, cur)
		if g.reg != nil {
			if n := g.reg.evictIdle(g.evictBatch); n > 0 {
				g.hardEvicted.Add(uint64(n))
				log.Printf("ntr: mem-guard HARD 踢最久空闲连接 %d 条(RSS=%s ≥ hard=%s)", n, human(cur), human(g.hardBytes))
			}
		}
	case g.softBytes > 0 && cur >= g.softBytes:
		g.setPhase(MemSoft, cur)
	default:
		g.setPhase(MemNormal, cur)
	}
}

// setPhase 置档位;仅在跃迁时记一行日志(soft/hard WARN/ERROR,回落 normal 记恢复),不刷屏。
func (g *MemGuard) setPhase(p MemPhase, cur uint64) {
	g.phase.Store(int32(p))
	if g.lastPhaseLog.Swap(int32(p)) == int32(p) {
		return
	}
	switch p {
	case MemSoft:
		log.Printf("ntr: mem-guard SOFT 进入拒新档(RSS=%s ≥ soft=%s);已建立连接不动", human(cur), human(g.softBytes))
	case MemHard:
		log.Printf("ntr: mem-guard HARD 进入踢连接档(RSS=%s ≥ hard=%s)", human(cur), human(g.hardBytes))
	default:
		log.Printf("ntr: mem-guard 回落 normal(RSS=%s)", human(cur))
	}
}

// MemStat 是 mem-guard 状态快照(供机器状态面 §5 暴露当前处于哪一档)。
type MemStat struct {
	Phase        string `json:"phase"`
	CurrentBytes uint64 `json:"current_bytes"`
	LimitBytes   uint64 `json:"limit_bytes"`
	SoftBytes    uint64 `json:"soft_bytes"`
	HardBytes    uint64 `json:"hard_bytes"`
	SoftRejected uint64 `json:"soft_rejected"`
	HardEvicted  uint64 `json:"hard_evicted"`
}

// Stat 返回当前状态快照。
func (g *MemGuard) Stat() MemStat {
	return MemStat{
		Phase:        MemPhase(g.phase.Load()).String(),
		CurrentBytes: g.sample(),
		LimitBytes:   g.limitBytes,
		SoftBytes:    g.softBytes,
		HardBytes:    g.hardBytes,
		SoftRejected: g.softRejected.Load(),
		HardEvicted:  g.hardEvicted.Load(),
	}
}

// currentMemBytes 返回当前内存占用(优先进程 RSS —— OOM killer 看的是它)。Linux 读 /proc/self/statm
// 的 resident 字段;读不到(非 Linux / 无 procfs)回退 Go 运行时向 OS 取用且未归还的内存(近似)。
func currentMemBytes() uint64 {
	if rss := procRSS(); rss > 0 {
		return rss
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.Sys - ms.HeapReleased
}

// procRSS 读 /proc/self/statm 第二字段(resident pages)× 页大小;非 Linux 或失败返回 0。
func procRSS() uint64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	// 格式:"size resident shared ..."(单位:页)。取第二个。
	i := 0
	for i < len(b) && b[i] != ' ' {
		i++
	}
	i++ // 跳过空格
	j := i
	for j < len(b) && b[j] != ' ' {
		j++
	}
	if j <= i {
		return 0
	}
	pages, err := strconv.ParseUint(string(b[i:j]), 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}

// human 把字节数格式化为易读串(状态面/日志用)。
func human(b uint64) string {
	const u = 1024
	if b < u {
		return strconv.FormatUint(b, 10) + "B"
	}
	div, exp := uint64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return strconv.FormatFloat(float64(b)/float64(div), 'f', 1, 64) + string("KMGTPE"[exp]) + "iB"
}
