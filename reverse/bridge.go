package reverse

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/muxcool"
)

// Bridge 是内网侧:主动经代理出站(Dial)拨到 Portal 建反连隧道,在每条隧道上跑 Mux.cool
// 服务端(ServerWorker),把 Portal 开来的用户子流【直连落地】到本地内网(Dialer)。
//
// 维持 Pool 条隧道;任一条断开即重连(短延迟)。Run 阻塞至 ctx 取消。
type Bridge struct {
	Dial      StreamDialer   // 到 Portal 的代理出站(任意协议)
	Control   addr.Socksaddr // 控制域(隧道注册目标,通常 fqdn + port 0)
	Dialer    net.Dialer     // 本地落地拨号器(direct)
	Pool      int            // 维持的隧道数(默认 1)
	Backoff   time.Duration  // 拨号失败重连退避(默认 3s)
	OnControl func([]byte)   // 控制心跳回调(可 nil:消费但不解析)
}

// Run 起 Pool 个 goroutine 各自维持一条隧道;阻塞至 ctx 取消。
func (b *Bridge) Run(ctx context.Context) error {
	n := b.Pool
	if n <= 0 {
		n = 1
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.maintain(ctx)
		}()
	}
	wg.Wait()
	return ctx.Err()
}

// maintain 维持一条隧道:拨号 → 跑 ServerWorker → 断则重连,直到 ctx 取消。
func (b *Bridge) maintain(ctx context.Context) {
	backoff := b.Backoff
	if backoff <= 0 {
		backoff = 3 * time.Second
	}
	for {
		if ctx.Err() != nil {
			return
		}
		stream, err := b.Dial.DialStream(ctx, b.Control)
		if err != nil {
			if !sleepCtx(ctx, backoff) {
				return
			}
			continue
		}
		// 懒发送传输(hy1/hy2/tuic 等 QUIC:DialStream 不立即发目标 header,首次 Write 才 flush)。
		// muxcool ServerWorker 建立后先读不写 → Portal 收不到隧道注册 header,而本端 Read 又阻塞
		// 等 Portal 响应 → 双向死锁。主动 flush 空写发出目标 header,让 Portal 立即感知本隧道并当
		// ClientWorker 起复用。eager 传输(vless/anytls/trojan/ss over tls)不实现 NeedHandshake,
		// ok=false 跳过,零影响。
		if fl, ok := stream.(interface{ NeedHandshake() bool }); ok && fl.NeedHandshake() {
			_, _ = stream.Write(nil)
		}
		w := muxcool.NewServerWorker(stream, directDispatcher{ctx: ctx, dialer: b.Dialer}, b.OnControl)
		// ctx 取消 → w.Close():关 link 打断阻塞在 ReadFrame 的读环,并关所有子流 inW 打断
		// 可能卡在 bufPipe.Write 的读环(HoL 背压下 Run 停在写而非读,单靠 stream.Close 唤不醒)。
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = w.Close()
			case <-done:
			}
		}()
		_ = w.Run() // 阻塞到隧道断
		close(done)
		if ctx.Err() != nil {
			return
		}
		// 隧道断,短延迟后重连(避免刚建就断时狂重连)。
		if !sleepCtx(ctx, 500*time.Millisecond) {
			return
		}
	}
}
