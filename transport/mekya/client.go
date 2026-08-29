package mekya

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// idlePollInterval 是无上行数据时的轮询间隔(拉下行);有上行数据则立即 POST。meek 本质是轮询,
// 该值权衡时延与请求率(mihomo 用自适应区间 + 连接池,此处单连接固定区间,线格式无关)。
const idlePollInterval = 20 * time.Millisecond

// maxBatchPackets 单次 POST 捆绑的最大 KCP 包数。
const maxBatchPackets = 64

// meekClientConn 是一条 mekya 客户端会话,实现 net.Conn 的【数据报】语义(每 Read/Write 一个 KCP 包),
// 供 mkcpcore.Dial 在其上跑 KCP。Write 入队 → 轮询 goroutine POST;Read 出队 ← POST 响应解捆绑。
type meekClientConn struct {
	sessionID string // base64url(16B)
	url        string
	hc         *http.Client
	local      net.Addr
	remote     net.Addr

	writerCh chan []byte
	readerCh chan []byte
	closeOnce sync.Once
	closeCh   chan struct{}
}

func newMeekClientConn(url string, remote net.Addr, tlsConf *tls.Config) (*meekClientConn, error) {
	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, err
	}
	// mekya 是 KCP-over-HTTPS(mihomo 强制 https + h2)。TLS 由 mekya 自带,ForceAttemptHTTP2 让其协商 h2。
	tr := &http.Transport{MaxIdleConnsPerHost: 4, TLSClientConfig: tlsConf, ForceAttemptHTTP2: true}
	c := &meekClientConn{
		sessionID: base64.RawURLEncoding.EncodeToString(sid[:]),
		url:       url,
		hc:        &http.Client{Transport: tr, Timeout: 30 * time.Second},
		local:     mekyaAddr("client"),
		remote:    remote,
		writerCh:  make(chan []byte, 256),
		readerCh:  make(chan []byte, 256),
		closeCh:   make(chan struct{}),
	}
	go c.pollLoop()
	return c, nil
}

// pollLoop 顺序轮询:有上行则立即 POST,否则每 idlePollInterval POST 一次拉下行;响应解捆绑入 readerCh。
func (c *meekClientConn) pollLoop() {
	timer := time.NewTimer(idlePollInterval)
	defer timer.Stop()
	for {
		var batch [][]byte
		// 先非阻塞收集已入队上行包
		batch = drain(c.writerCh, batch, maxBatchPackets)
		if len(batch) == 0 {
			// 无上行:等数据或轮询定时器
			timer.Reset(idlePollInterval)
			select {
			case p := <-c.writerCh:
				batch = append(batch, p)
				batch = drain(c.writerCh, batch, maxBatchPackets)
			case <-timer.C:
			case <-c.closeCh:
				return
			}
		}
		if !c.roundTrip(batch) {
			return
		}
	}
}

// drain 非阻塞地把 ch 里已有的包追加进 batch,至多到 max。
func drain(ch chan []byte, batch [][]byte, max int) [][]byte {
	for len(batch) < max {
		select {
		case p := <-ch:
			batch = append(batch, p)
		default:
			return batch
		}
	}
	return batch
}

// roundTrip 把 batch 捆绑成请求体 POST,读响应解捆绑入 readerCh。返回 false 表示应停止(致命错/关闭)。
func (c *meekClientConn) roundTrip(batch [][]byte) bool {
	body := bytes.NewBuffer(nil)
	for _, p := range batch {
		if writePacketBundle(body, p) != nil {
			return true // 跳过坏包,继续
		}
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.url, bytes.NewReader(body.Bytes()))
	if err != nil {
		return false
	}
	req.Header.Set("X-Session-ID", c.sessionID)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.hc.Do(req)
	if err != nil {
		select {
		case <-c.closeCh:
			return false
		default:
			return true // 瞬时错,下轮重试
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return true
	}
	for {
		pkt, err := readPacketBundle(resp.Body)
		if err != nil {
			break
		}
		select {
		case c.readerCh <- pkt:
		case <-c.closeCh:
			return false
		}
	}
	return true
}

// Read 出队一个下行 KCP 包(数据报语义)。
func (c *meekClientConn) Read(p []byte) (int, error) {
	select {
	case pkt := <-c.readerCh:
		return copy(p, pkt), nil
	case <-c.closeCh:
		return 0, io.EOF
	}
}

// Write 入队一个上行 KCP 包(拷贝,由轮询 goroutine POST)。
func (c *meekClientConn) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case c.writerCh <- cp:
		return len(p), nil
	case <-c.closeCh:
		return 0, net.ErrClosed
	}
}

func (c *meekClientConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		c.hc.CloseIdleConnections()
	})
	return nil
}

func (c *meekClientConn) LocalAddr() net.Addr                { return c.local }
func (c *meekClientConn) RemoteAddr() net.Addr               { return c.remote }
func (c *meekClientConn) SetDeadline(time.Time) error      { return nil } // mkcpcore 不在 raw 上用 deadline
func (c *meekClientConn) SetReadDeadline(time.Time) error  { return nil }
func (c *meekClientConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*meekClientConn)(nil)

// mekyaAddr 是占位 net.Addr(mkcpcore 只用它作 local/remote 标签)。
type mekyaAddr string

func (a mekyaAddr) Network() string { return "mekya" }
func (a mekyaAddr) String() string  { return string(a) }
