package meter

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LOVECHEN/ntr/core/cred"
)

// Limits 是一个计费槽(用户)的限制(承设计 §6.2 每用户;0 = 不限)。
type Limits struct {
	MaxConns int64   // 并发连接上限(0=不限)
	Rate     float64 // 吞吐上限,字节/秒(0=不限;up+down 合计)
	MaxIPs   int     // 同时在线的不同源 IP 数上限,防共享(0=不限)
}

// rateLimiter 是令牌桶,在【稀疏泄流点】(每 T 字节)调一次 throttle,而非每字节(承 §6.3.1)。
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64 // bytes/sec
	burst  float64
	tokens float64
	last   time.Time
}

func newRateLimiter(rate float64) *rateLimiter {
	burst := rate // 1s 突发
	if burst < 256*1024 {
		burst = 256 * 1024
	}
	return &rateLimiter{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

// throttle 消耗 n 令牌;不足则 sleep 到补齐(在中继 goroutine 里 sleep → 背压 → 限速)。
func (r *rateLimiter) throttle(n int) {
	r.mu.Lock()
	now := time.Now()
	r.tokens += r.rate * now.Sub(r.last).Seconds()
	if r.tokens > r.burst {
		r.tokens = r.burst
	}
	r.last = now
	r.tokens -= float64(n)
	var sleep time.Duration
	if r.tokens < 0 {
		sleep = time.Duration(-r.tokens / r.rate * float64(time.Second))
	}
	r.mu.Unlock()
	if sleep > 0 {
		time.Sleep(sleep)
	}
}

// ipGate 限「同时在线的不同源 IP 数」。老 IP 再来只 refcount++、不占新槽(承 §6.3.3;NAT 后多连接算 1 IP)。
// MVP 只做 reject(满即拒新 IP);evict-oldest(§6.7)后续。
type ipGate struct {
	mu       sync.Mutex
	ips      map[netip.Addr]int // 活源 IP → refcount
	cap      int
	rejected atomic.Uint64
}

func newIPGate(cap int) *ipGate { return &ipGate{ips: make(map[netip.Addr]int), cap: cap} }

func (g *ipGate) acquire(ip netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, hit := g.ips[ip]; hit { // 老 IP:refcount++,不占新槽
		g.ips[ip]++
		return true
	}
	if g.cap != 0 && len(g.ips) >= g.cap { // 新 IP 且已满 → 拒(必计数,§6.4.2)
		g.rejected.Add(1)
		return false
	}
	g.ips[ip] = 1
	return true
}

func (g *ipGate) release(ip netip.Addr) {
	g.mu.Lock()
	if n := g.ips[ip]; n > 1 {
		g.ips[ip] = n - 1
	} else {
		delete(g.ips, ip)
	}
	g.mu.Unlock()
}

// Gate 是【全局 / 每口】层的连接闸(承 §6.2 层 1/2;非 per-user,故独立于 Cell)。max-conns 接入 CAS。
// 叠加检查顺序:全局 → 口 → 用户,任一超即拒(§6.2.2)。rate 为全局/每口限速(挂稀疏泄流点)。
type Gate struct {
	maxConns int64 // 0=不限
	live     atomic.Int64
	rejected atomic.Uint64
	rate     *rateLimiter // nil=不限
}

// NewGate 建闸;maxConns=0 且 rate=0 时返回 nil(该层无限制,免开销)。
func NewGate(maxConns int64, rate float64) *Gate {
	if maxConns == 0 && rate == 0 {
		return nil
	}
	g := &Gate{maxConns: maxConns}
	if rate > 0 {
		g.rate = newRateLimiter(rate)
	}
	return g
}

// TryAcquire:接入时一次 CAS(nil 闸恒通)。触顶 → 拒 + 计数。
func (g *Gate) TryAcquire() bool {
	if g == nil {
		return true
	}
	if g.maxConns == 0 {
		g.live.Add(1)
		return true
	}
	for {
		cur := g.live.Load()
		if cur >= g.maxConns {
			g.rejected.Add(1)
			return false
		}
		if g.live.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// Release:连接收尾一次(nil 闸 no-op)。
func (g *Gate) Release() {
	if g != nil {
		g.live.Add(-1)
	}
}

// Throttle:稀疏泄流点限速(nil / 无 rate 时 no-op)。
func (g *Gate) Throttle(n int) {
	if g != nil && g.rate != nil {
		g.rate.throttle(n)
	}
}

// SetLimits 给一个凭据设限(config 期,连接开始前)。maxConns 原地 atomic 更新(reload InPlace,零断连);
// rate/maxIPs 建/换(config 期,无并发)。
func (r *Registry) SetLimits(id cred.ID, l Limits) {
	c := r.cell(id)
	c.maxConns.Store(l.MaxConns)
	if l.Rate > 0 {
		c.rate = newRateLimiter(l.Rate)
	}
	if l.MaxIPs > 0 {
		c.ipg = newIPGate(l.MaxIPs)
	}
}

// tryAcquireConn:接入时一次 CAS(承 §6.3.2,无 overshoot);cap=0 不限。管理 connsLive。
func (c *Cell) tryAcquireConn() bool {
	cap := c.maxConns.Load()
	if cap == 0 {
		c.connsLive.Add(1)
		return true
	}
	for {
		cur := c.connsLive.Load()
		if cur >= cap {
			c.rejectedConns.Add(1)
			return false
		}
		if c.connsLive.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (c *Cell) releaseConn() { c.connsLive.Add(-1) }
