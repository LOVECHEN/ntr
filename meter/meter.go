// Package meter 是计量子系统(承设计 §5,MVP)。核心技法:热路径【0 原子/Read】—— 每连接 goroutine
// 私有 local 累计(非原子、单写者),每 T 字节才稀疏 drain 一次到共享 Cell 的原子计数(对比 mihomo
// ~3 原子/Read、ssmu 1 原子/Read)。按 cred.ID(用户/计费槽)聚合,面板经 Snapshot 读每用户 up/down/连接数。
//
// MVP 范围:按用户聚合的 payload 字节 + 连接数(total/live);L=Cred 粒度(每用户一 Cell)。稀疏化 drain。
// Phase 2:粒度旋钮(Service/IP/Conn)、seqlock scrape 一致性、速率结算、wire 字节(栈底 leaf)。
package meter

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LOVECHEN/ntr/core/cred"
)

// drainThreshold 是稀疏 drain 阈值 T(字节):local 累够 T 才原子加一次到 Cell。
const drainThreshold = 128 * 1024

// connHandle 是一条活连接的杀点 + 活跃时间戳(承 §6.5.1「计量树就是开关树」+ §6.4bis.3 踢最久空闲)。
// kill 断两端(幂等);lastActive 是最近一次 drain(有数据流动)的 unix 纳秒,mem-guard 硬阈值据此排序
// 踢「最久无数据传输」的连接。lastActive 单点原子:热路径每 T 字节写一次(稀疏),踢连接侧读快照。
type connHandle struct {
	kill       func()
	lastActive atomic.Int64
}

// Cell 是一个计费槽(用户)的原子计数 + 热开关状态(承 §6.5「计量树就是开关树」)。
type Cell struct {
	up         atomic.Uint64 // 应用层上行字节(client→target)
	down       atomic.Uint64 // 应用层下行字节(target→client)
	connsTotal atomic.Uint64 // 单调累计连接数
	connsLive  atomic.Int64  // 当前活跃连接

	disabled atomic.Bool            // 热开关:停用(拒新 + 断老,承 §6.5.2)
	liveMu   sync.Mutex             // 配对 disabled 检查与 live 增删(D-01 竞态修法,承 §6.5.5)
	live     map[uint64]*connHandle // connID → 杀点+活跃戳(KillConn/killAll/mem-guard 踢空闲 用)

	// 限制(承 §6.2 每用户;config 期设,连接前;0/nil = 不限)。
	maxConns      atomic.Int64  // 并发连接上限(原地 atomic 更新支持 reload InPlace);shared 非 nil 时不用
	rejectedConns atomic.Uint64 // 因 max-conns 触顶被拒的连接数(§6.4.2 必计数)
	rate          *rateLimiter  // 吞吐令牌桶(稀疏泄流点 throttle);shared 时指向共享桶
	ipg           *ipGate       // 同时在线不同源 IP 数限制;shared 时指向共享闸
	shared        *sharedLimit  // 按人合计的限流单元(同一 user 各 BillID 的 Cell 共指);nil = 单 Cell 自限
}

// addGuarded 在同一把锁下【先查 disabled 再登记】:已停用则拒绝登记(调用方关连接),消除 D-01 幽灵连接。
func (c *Cell) addGuarded(connID uint64, h *connHandle) bool {
	c.liveMu.Lock()
	defer c.liveMu.Unlock()
	if c.disabled.Load() {
		return false
	}
	if c.live == nil {
		c.live = make(map[uint64]*connHandle)
	}
	c.live[connID] = h
	return true
}

func (c *Cell) removeLive(connID uint64) {
	c.liveMu.Lock()
	delete(c.live, connID)
	c.liveMu.Unlock()
}

// killAll 断该 Cell 的全部活连接,返回条数(在锁内取快照,异步 close 免死锁)。
func (c *Cell) killAll() int {
	c.liveMu.Lock()
	kills := make([]func(), 0, len(c.live))
	for _, h := range c.live {
		kills = append(kills, h.kill)
	}
	c.live = make(map[uint64]*connHandle)
	c.liveMu.Unlock()
	for _, k := range kills {
		go k()
	}
	return len(kills)
}

// Registry 按 cred.ID 聚合 Cell(每凭据一个)。热路径只读;Cell 建后不删(凭据集稳定)。
//
// 它同时是【BillID ↔ 数字句柄】的分配权所在:配置层的稳定身份是 BillID("name@inbound",承第 4 章
// 规则 5),运行时热路径只认 cred.ID。分配放这里(而非 config 局部)的原因是 Registry 跨热重载复用 ——
// 同一 bill 在下一代配置里拿到同一个 id,面板存下的 id 不会在 reload 后指向别人。
type Registry struct {
	mu      sync.RWMutex
	cells   map[cred.ID]*Cell
	connSeq atomic.Uint64 // 全局 connID 分配
	idx     sync.Map      // connID(uint64) → *Cell,供 KillConn 全局定位

	bills  map[string]cred.ID // BillID → id(同 bill 恒同 id)
	labels map[cred.ID]string // id → BillID(对外报标签 / 反查)
	nextID cred.ID            // 下一个空位;从 UserBase+1 起,不占 Unmatched(0)/Ambient(1) 保留位
}

// NewRegistry 建注册表。
func NewRegistry() *Registry {
	return &Registry{
		cells:  make(map[cred.ID]*Cell),
		bills:  make(map[string]cred.ID),
		labels: make(map[cred.ID]string),
		nextID: cred.UserBase + 1,
	}
}

// IDForBill 把稳定计费身份 BillID 映射到运行时数字句柄:同 bill 恒同 id(跨 reload 复用),新 bill 分配
// 下一个空位。并发安全;幂等。
func (r *Registry) IDForBill(bill string) cred.ID {
	r.mu.RLock()
	id, ok := r.bills[bill]
	r.mu.RUnlock()
	if ok {
		return id
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok = r.bills[bill]; ok {
		return id
	}
	id = r.nextID
	r.nextID++
	r.bills[bill] = id
	r.labels[id] = bill
	return id
}

// IDByBill 反查:只读,不分配。
func (r *Registry) IDByBill(bill string) (cred.ID, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.bills[bill]
	return id, ok
}

// Bill 报 id 的 BillID 标签(未登记为空串)。
func (r *Registry) Bill(id cred.ID) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.labels[id]
}

// cell 取 id 的 Cell(不存在则建)。
func (r *Registry) cell(id cred.ID) *Cell {
	r.mu.RLock()
	c := r.cells[id]
	r.mu.RUnlock()
	if c != nil {
		return c
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c = r.cells[id]; c == nil {
		c = &Cell{}
		r.cells[id] = c
	}
	return c
}

// Open 在一条连接接入时登记。kill 是断连函数(Disable/KillConn 用,关客户端+出站流)。
// 返回 (Meter, done, admitted):admitted=false 表示该用户已被 Disable(拒新)→ 调用方立即关连接。
// 登记走 addGuarded(与 disabled 检查同锁),消除 D-01 幽灵连接(承 §6.5.5)。
func (r *Registry) Open(id cred.ID, src netip.Addr, kill func()) (*Meter, func(), bool) {
	c := r.cell(id)
	// max-ips(防共享):新源 IP 且已满 → 拒。
	if c.ipg != nil && !c.ipg.acquire(src) {
		return nil, nil, false
	}
	// max-conns:接入一次 CAS(管理 connsLive)。
	if !c.tryAcquireConn() {
		if c.ipg != nil {
			c.ipg.release(src)
		}
		return nil, nil, false
	}
	connID := r.connSeq.Add(1)
	h := &connHandle{kill: kill}
	h.lastActive.Store(time.Now().UnixNano()) // 建连即算一次活跃(避免刚接入就被判「最久空闲」误踢)
	if !c.addGuarded(connID, h) {             // 已被 Disable(热开关)→ 拒
		c.releaseConn()
		if c.ipg != nil {
			c.ipg.release(src)
		}
		return nil, nil, false
	}
	c.connsTotal.Add(1)
	r.idx.Store(connID, c)
	m := &Meter{cell: c, h: h}
	return m, func() {
		m.Flush()
		c.releaseConn()
		if c.ipg != nil {
			c.ipg.release(src)
		}
		c.removeLive(connID)
		r.idx.Delete(connID)
	}, true
}

// Disable 停用一个凭据:拒新握手 + 断其全部活连接(承 §6.5.2)。返回断了多少条。
func (r *Registry) Disable(id cred.ID) (killed int, ok bool) {
	r.mu.RLock()
	c := r.cells[id]
	r.mu.RUnlock()
	if c == nil {
		return 0, false
	}
	c.disabled.Store(true)   // ① 先置位:此后 addGuarded 拒新
	return c.killAll(), true // ② 再断老(与 addGuarded 同锁,无中间态)
}

// Enable 恢复一个凭据(拒新解除;停用期间的累计流量仍在计数里,面板可见)。
func (r *Registry) Enable(id cred.ID) bool {
	r.mu.RLock()
	c := r.cells[id]
	r.mu.RUnlock()
	if c == nil {
		return false
	}
	c.disabled.Store(false)
	return true
}

// KillConn 断单条连接(不拒新;凭据仍有效可重连)。返回 1(断了)或 0(已亡/不存在)。
func (r *Registry) KillConn(connID uint64) int {
	v, ok := r.idx.Load(connID)
	if !ok {
		return 0
	}
	c := v.(*Cell)
	c.liveMu.Lock()
	h := c.live[connID]
	delete(c.live, connID)
	c.liveMu.Unlock()
	if h == nil {
		return 0
	}
	go h.kill()
	return 1
}

// evictIdle 踢最多 n 条「最久无数据传输」的活连接(承 §6.4bis.3:mem-guard 硬阈值止损)。按 lastActive
// 升序(最久空闲优先)全局排序,在锁下摘除再异步 kill(摘除防同一条被下一轮重复选中)。返回实际踢掉条数。
// 只有登记进 Registry 的连接(即计量开启时接入的)才在候选集里 —— 计量关闭时本函数为空操作(诚实:
// 硬阈值踢连接依赖计量注册,承第三道防线的前提)。
func (r *Registry) evictIdle(n int) int {
	if n <= 0 {
		return 0
	}
	type ent struct {
		cell *Cell
		id   uint64
		last int64
		kill func()
	}
	r.mu.RLock()
	cells := make([]*Cell, 0, len(r.cells))
	for _, c := range r.cells {
		cells = append(cells, c)
	}
	r.mu.RUnlock()
	var ents []ent
	for _, c := range cells {
		c.liveMu.Lock()
		for id, h := range c.live {
			ents = append(ents, ent{cell: c, id: id, last: h.lastActive.Load(), kill: h.kill})
		}
		c.liveMu.Unlock()
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].last < ents[j].last }) // 最久空闲在前
	killed := 0
	for _, e := range ents {
		if killed >= n {
			break
		}
		e.cell.liveMu.Lock()
		_, still := e.cell.live[e.id]
		if still {
			delete(e.cell.live, e.id) // 先摘除:防本轮踢的连接在下一 tick 再次入选
		}
		e.cell.liveMu.Unlock()
		if still {
			go e.kill()
			killed++
		}
	}
	return killed
}

// Meter 是每连接计量器。localUp 仅由 Read 侧 goroutine 写、localDown 仅由 Write 侧写(relay 的两个
// copyStream 各一 goroutine)—— 故各为单写者,无需原子、无数据竞争。
type Meter struct {
	cell    *Cell       // per-user Cell(可 nil:仅全局/每口限速的 gate-only 计量器)
	h       *connHandle // 本连接杀点+活跃戳(mem-guard 踢空闲用;gate-only / 无注册时 nil)
	gates   []*Gate     // 全局 + 每口(rate 在稀疏泄流点一并 throttle;可空)
	localUp uint64      // 单写者(Read goroutine)
	localDn uint64      // 单写者(Write goroutine)
}

// touch 在稀疏 drain 点更新活跃戳(有数据流动即刷新;mem-guard 硬阈值据此判「最久空闲」)。
// 每 T 字节至多一次,非每字节 —— 与 drain 同频,几乎零成本。h 为 nil(gate-only)时空操作。
func (m *Meter) touch() {
	if m.h != nil {
		m.h.lastActive.Store(time.Now().UnixNano())
	}
}

// GateMeter 建一个仅承载 gate 限速的计量器(metering 关但全局/每口有 rate 时用;cell=nil)。
func GateMeter(gates []*Gate) *Meter { return &Meter{gates: gates} }

// WithGates 给 Meter 附上全局/每口闸(其 rate 在 drain 一并 throttle)。返回 m 便于链式。
func (m *Meter) WithGates(gates []*Gate) *Meter {
	if m != nil {
		m.gates = gates
	}
	return m
}

// AddUp 记上行 n 字节(Read 侧调用);累够 T 才 drain。
func (m *Meter) AddUp(n int) {
	if n <= 0 {
		return
	}
	m.localUp += uint64(n)
	if m.localUp >= drainThreshold {
		drained := int(m.localUp)
		m.touch() // 活跃戳(mem-guard 踢空闲)
		if m.cell != nil {
			m.cell.up.Add(m.localUp)
			if m.cell.rate != nil { // 用户层限速(承 §6.3.1;每 T 一次,非每字节)
				m.cell.rate.throttle(drained)
			}
		}
		for _, g := range m.gates { // 全局 / 每口层限速(串联,§6.2.3)
			g.Throttle(drained)
		}
		m.localUp = 0
	}
}

// AddDown 记下行 n 字节(Write 侧调用);累够 T 才 drain。
func (m *Meter) AddDown(n int) {
	if n <= 0 {
		return
	}
	m.localDn += uint64(n)
	if m.localDn >= drainThreshold {
		drained := int(m.localDn)
		m.touch() // 活跃戳(mem-guard 踢空闲)
		if m.cell != nil {
			m.cell.down.Add(m.localDn)
			if m.cell.rate != nil { // 用户层限速(下行;与上行共用同一桶 → 合计吞吐受限)
				m.cell.rate.throttle(drained)
			}
		}
		for _, g := range m.gates { // 全局 / 每口层限速
			g.Throttle(drained)
		}
		m.localDn = 0
	}
}

// Flush 把私有余量 drain 到 Cell(连接收尾时,relay 两 goroutine 均已结束,无并发)。cell=nil 时只清余量。
func (m *Meter) Flush() {
	if m.cell != nil {
		if m.localUp > 0 {
			m.cell.up.Add(m.localUp)
		}
		if m.localDn > 0 {
			m.cell.down.Add(m.localDn)
		}
	}
	m.localUp, m.localDn = 0, 0
}

// UserStat 是一个凭据的计量快照 + 开关状态。Bill 是稳定身份("name@inbound"),面板按它对账;
// ID 是本进程的运行时句柄(同 bill 跨 reload 复用,但仍不要跨机器/跨重启持久化 ID)。
type UserStat struct {
	ID         uint64 `json:"id"`
	Bill       string `json:"bill,omitempty"`
	Up         uint64 `json:"up"`
	Down       uint64 `json:"down"`
	ConnsTotal uint64 `json:"conns_total"`
	ConnsLive  int64  `json:"conns_live"`
	Disabled   bool   `json:"disabled"`
	MaxConns   int64  `json:"max_conns"`          // 0=不限
	Rejected   uint64 `json:"rejected,omitempty"` // 因 max-conns 触顶被拒的连接数
}

// Snapshot 返回所有用户的当前计量(按 ID 排序)。读原子计数,不含各连接未 drain 的私有余量
// (稀疏化的诚实代价:面板值滞后至多一个 T,连接收尾后精确)。
func (r *Registry) Snapshot() []UserStat {
	r.mu.RLock()
	out := make([]UserStat, 0, len(r.cells))
	for id, c := range r.cells {
		maxConns := c.maxConns.Load()
		if s := c.shared; s != nil {
			maxConns = s.maxConns // 按人合计的上限
		}
		out = append(out, UserStat{
			ID:         uint64(id),
			Bill:       r.labels[id],
			Up:         c.up.Load(),
			Down:       c.down.Load(),
			ConnsTotal: c.connsTotal.Load(),
			ConnsLive:  c.connsLive.Load(),
			Disabled:   c.disabled.Load(),
			MaxConns:   maxConns,
			Rejected:   c.rejectedConns.Load(),
		})
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
