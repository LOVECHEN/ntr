package reverse

import (
	"sync"

	"github.com/LOVECHEN/ntr/muxcool"
)

// pool 是 Portal 侧的隧道池:一组到各 Bridge 的 Mux.cool 客户端 worker。用户连接经 pick
// 轮询挑一个【活跃】worker 在其上开子流。worker 关闭(隧道断)后从池剔除。
type pool struct {
	mu      sync.Mutex
	workers []*muxcool.ClientWorker
	rr      int
}

// add 把一条新隧道 worker 入池。
func (p *pool) add(w *muxcool.ClientWorker) {
	p.mu.Lock()
	p.workers = append(p.workers, w)
	p.mu.Unlock()
}

// remove 把 worker 出池(隧道断时调用)。
func (p *pool) remove(w *muxcool.ClientWorker) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, x := range p.workers {
		if x == w {
			p.workers = append(p.workers[:i], p.workers[i+1:]...)
			return
		}
	}
}

// pick 轮询挑一个活跃(未关闭、未 DRAIN)worker;顺带剔除已死的。无可用返回 nil。
func (p *pool) pick() *muxcool.ClientWorker {
	p.mu.Lock()
	defer p.mu.Unlock()
	// 先剔除已死(Done 关闭)的 worker。
	live := p.workers[:0]
	for _, w := range p.workers {
		if !isDone(w) {
			live = append(live, w)
		}
	}
	p.workers = live
	n := len(p.workers)
	if n == 0 {
		return nil
	}
	// 从 rr 起最多扫一圈,挑第一个 IsActive(排除 DRAIN 中的)。
	for i := 0; i < n; i++ {
		p.rr = (p.rr + 1) % n
		if w := p.workers[p.rr]; w.IsActive() {
			return w
		}
	}
	return nil
}

// size 返回当前池内隧道数(测试/观测用)。
func (p *pool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.workers)
}

// isDone 报告 worker 是否已关闭(隧道断)。
func isDone(w *muxcool.ClientWorker) bool {
	select {
	case <-w.Done():
		return true
	default:
		return false
	}
}
