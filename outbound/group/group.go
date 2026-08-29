// Package group 是「组出站」:一个 endpoint.Outbound 在多个子出站间按策略选路。
// 选路是纯本地策略(select 手选 / urltest 测延迟 / fallback 首个可用 / load-balance 负载均衡),
// wire 上完全不可见 → 天然不碰任何协议线格式(禁改线格式一条不涉及)。成员本身也是 endpoint.Outbound,
// 故「组包组」天然成立;组名进 outs 后与 direct/block 同权,路由/入站零特判。
package group

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

// Strategy 选路策略。
type Strategy int

const (
	Select      Strategy = iota // 手选 default 成员(可经 metrics 端点运行时切换)
	URLTest                     // 周期测延迟,选最快 alive 成员(带 tolerance 防抖)
	Fallback                    // 按顺序返回第一个 alive 成员
	LoadBalance                 // 按 dst 分派:轮询 或 一致性哈希(同 dst 恒同出站)
)

// Member 组成员:名 + 子出站。
type Member struct {
	Name string
	Out  endpoint.Outbound
}

// Options 组配置。
type Options struct {
	Name      string
	Members   []Member
	Strategy  Strategy
	Default   string        // select/初始 选中成员名(空=第一个)
	TestURL   string        // 探测 URL(默认 http://www.gstatic.com/generate_204)
	Interval  time.Duration // 探测周期(默认 5m)
	Tolerance int           // urltest 抖动容差 ms(新最优快过当前超过它才切)
	LBHash    bool          // load-balance:true=一致性哈希(同 dst 恒同出站),false=轮询
}

type memState struct {
	delay time.Duration
	alive bool
}

// Group 实现 endpoint.Outbound。
type Group struct {
	opts     Options
	picked   atomic.Pointer[Member] // select/urltest/fallback 当前选中
	rr       atomic.Uint64          // load-balance 轮询游标
	mu       sync.Mutex
	state    map[string]*memState
	testAddr addr.Socksaddr
	testURL  string
}

var _ endpoint.Outbound = (*Group)(nil)

// New 构造组出站。
func New(opts Options) (*Group, error) {
	if len(opts.Members) == 0 {
		return nil, errors.New("group: 无成员")
	}
	if opts.TestURL == "" {
		opts.TestURL = "http://www.gstatic.com/generate_204"
	}
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Minute
	}
	u, err := url.Parse(opts.TestURL)
	if err != nil {
		return nil, fmt.Errorf("group %q: 测试 URL:%w", opts.Name, err)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	pn, _ := strconvAtoiPort(port)
	g := &Group{opts: opts, state: make(map[string]*memState, len(opts.Members)), testURL: opts.TestURL}
	if ip, e := netip.ParseAddr(host); e == nil {
		g.testAddr = addr.FromIPPort(netip.AddrPortFrom(ip, pn))
	} else {
		g.testAddr = addr.FromFqdn(host, pn)
	}
	init := opts.Members[0]
	for _, m := range opts.Members {
		if m.Name == opts.Default {
			init = m
			break
		}
		g.state[m.Name] = &memState{alive: true}
	}
	for _, m := range opts.Members {
		if g.state[m.Name] == nil {
			g.state[m.Name] = &memState{alive: true}
		}
	}
	g.picked.Store(&init)
	return g, nil
}

func strconvAtoiPort(s string) (uint16, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil || n < 0 || n > 65535 {
		return 80, err
	}
	return uint16(n), nil
}

// SelectOutbound 运行时手选(select 组;供 metrics 端点调用)。
func (g *Group) SelectOutbound(name string) bool {
	for i := range g.opts.Members {
		if g.opts.Members[i].Name == name {
			g.picked.Store(&g.opts.Members[i])
			return true
		}
	}
	return false
}

func (g *Group) DialStream(ctx context.Context, dst addr.Socksaddr) (link.Stream, error) {
	m := g.pick(dst)
	if m == nil {
		return nil, errors.New("group: 无可用成员")
	}
	return m.Out.DialStream(ctx, dst)
}

func (g *Group) DialPacket(ctx context.Context, dst addr.Socksaddr) (link.PacketConn, error) {
	m := g.pick(dst)
	if m == nil {
		return nil, errors.New("group: 无可用成员")
	}
	return m.Out.DialPacket(ctx, dst)
}

func (g *Group) pick(dst addr.Socksaddr) *Member {
	if g.opts.Strategy == LoadBalance {
		return g.pickLB(dst)
	}
	return g.picked.Load()
}

func (g *Group) pickLB(dst addr.Socksaddr) *Member {
	ms := g.opts.Members
	if g.opts.LBHash {
		h := fnv.New32a()
		_, _ = h.Write([]byte(dst.String()))
		start := int(h.Sum32()) % len(ms)
		for i := 0; i < len(ms); i++ {
			idx := (start + i) % len(ms)
			if g.aliveOf(ms[idx].Name) {
				return &ms[idx]
			}
		}
		return &ms[start]
	}
	for i := 0; i < len(ms); i++ {
		idx := int(g.rr.Add(1)) % len(ms)
		if g.aliveOf(ms[idx].Name) {
			return &ms[idx]
		}
	}
	return &ms[int(g.rr.Load())%len(ms)]
}

func (g *Group) aliveOf(name string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.state[name]
	return s == nil || s.alive
}

// Name 返回组名(供 config 挂 health-loop Instance 标签)。
func (g *Group) Name() string { return g.opts.Name }

// NeedsHealth 报告是否需要后台探测循环(select 手选不需要)。
func (g *Group) NeedsHealth() bool { return g.opts.Strategy != Select }

// HealthLoop 周期探测所有成员、更新 alive/delay,并按策略重选。挂成 config.Instance{Run}。
func (g *Group) HealthLoop(ctx context.Context) error {
	g.probeAll(ctx)
	t := time.NewTicker(g.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			g.probeAll(ctx)
		}
	}
}

func (g *Group) probeAll(ctx context.Context) {
	var wg sync.WaitGroup
	for i := range g.opts.Members {
		m := g.opts.Members[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, ok := g.probe(ctx, m)
			g.mu.Lock()
			g.state[m.Name] = &memState{delay: d, alive: ok}
			g.mu.Unlock()
		}()
	}
	wg.Wait()
	g.reselect()
}

// probe 经成员出站拨测试 URL 的 host,发 HEAD,量 RTT。stream 内嵌 net.Conn 直接喂 http.Transport。
func (g *Group) probe(ctx context.Context, m Member) (time.Duration, bool) {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tr := &http.Transport{
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			return m.Out.DialStream(dctx, g.testAddr)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(tctx, http.MethodHead, g.testURL, nil)
	if err != nil {
		return 0, false
	}
	start := time.Now()
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return 0, false
	}
	_ = resp.Body.Close()
	return time.Since(start), true
}

// reselect:urltest→min-delay alive(tolerance 防抖);fallback→首个 alive;select/LB 不动 picked。
func (g *Group) reselect() {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch g.opts.Strategy {
	case URLTest:
		var best *Member
		var bestD time.Duration
		cur := g.picked.Load()
		curD := time.Duration(1) << 62
		if cur != nil {
			if s := g.state[cur.Name]; s != nil && s.alive {
				curD = s.delay
			}
		}
		for i := range g.opts.Members {
			m := &g.opts.Members[i]
			s := g.state[m.Name]
			if s == nil || !s.alive {
				continue
			}
			if best == nil || s.delay < bestD {
				best, bestD = m, s.delay
			}
		}
		if best != nil && (cur == nil || bestD+time.Duration(g.opts.Tolerance)*time.Millisecond < curD) {
			g.picked.Store(best)
		}
	case Fallback:
		for i := range g.opts.Members {
			m := &g.opts.Members[i]
			if s := g.state[m.Name]; s != nil && s.alive {
				g.picked.Store(m)
				return
			}
		}
	}
}
