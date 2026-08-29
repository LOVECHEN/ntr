package mekya

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// respDrainWait 是服务端喂完请求上行包后、为凑齐同响应下行包等待 KCP 产出的上限。
// ★须 > KCP TTI(默认 50ms):meek 半双工,服务端只能在响应里回下行 KCP 包;若等待 < TTI,
// KCP 在下个 tick 才产出的 ACK/数据会被漏进本响应 → 握手/数据卡顿。取 80ms 稳超 TTI。
const respDrainWait = 80 * time.Millisecond

// maxRespPackets 单个响应捆绑的最大下行包数。
const maxRespPackets = 64

// sessionIdle 超过此时长无请求的会话被回收。
const sessionIdle = 90 * time.Second

type inPacket struct {
	data []byte
	addr net.Addr
}

type serverSession struct {
	addr net.Addr
	outCh chan []byte
	last  time.Time
}

// meekServerPacketConn 把 meek HTTP 会话多路复用成一个 net.PacketConn:请求体上行包 → ReadFrom
// (带会话 addr);WriteTo(下行包, 会话 addr)→ 该会话响应队列。供 mkcpcore.Listen 在其上跑 KCP。
type meekServerPacketConn struct {
	inbox chan inPacket
	mu    sync.Mutex
	sess  map[string]*serverSession
	local net.Addr

	closeOnce sync.Once
	closeCh   chan struct{}
}

func newMeekServerPacketConn() *meekServerPacketConn {
	pc := &meekServerPacketConn{
		inbox:   make(chan inPacket, 1024),
		sess:    map[string]*serverSession{},
		local:   mekyaAddr("server"),
		closeCh: make(chan struct{}),
	}
	go pc.reaper()
	return pc
}

func (pc *meekServerPacketConn) getSession(sid string) *serverSession {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	s := pc.sess[sid]
	if s == nil {
		s = &serverSession{addr: mekyaAddr(sid), outCh: make(chan []byte, 256)}
		pc.sess[sid] = s
	}
	s.last = time.Now()
	return s
}

// ServeHTTP 处理一次 meek 轮询:解请求体上行包喂 inbox,再凑该会话下行包回响应。
func (pc *meekServerPacketConn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("X-Session-ID")
	if sid == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	s := pc.getSession(sid)
	// 上行:读满请求体(对齐 mihomo io.ReadAll)再解捆绑 → inbox(带会话 addr)
	raw, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	rd := bytes.NewReader(raw)
	for {
		pkt, err := readPacketBundle(rd)
		if err != nil {
			break
		}
		select {
		case pc.inbox <- inPacket{data: pkt, addr: s.addr}:
		case <-pc.closeCh:
			return
		}
	}
	// 下行:等 KCP 产出该会话的包(至多 respDrainWait),凑进响应
	body := bytes.NewBuffer(nil)
	timer := time.NewTimer(respDrainWait)
	defer timer.Stop()
	n := 0
	for n < maxRespPackets {
		select {
		case p := <-s.outCh:
			_ = writePacketBundle(body, p)
			n++
			continue // 已有包就继续非阻塞多收
		case <-timer.C:
		case <-pc.closeCh:
		}
		break
	}
	// 首包等到后,再非阻塞把当前可取的都收进来
drain2:
	for n < maxRespPackets {
		select {
		case p := <-s.outCh:
			_ = writePacketBundle(body, p)
			n++
		default:
			break drain2
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body.Bytes())
}

// ReadFrom 出队一个上行 KCP 包 + 其会话 addr(供 mkcpcore 路由 KCP 会话)。
func (pc *meekServerPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case in := <-pc.inbox:
		return copy(p, in.data), in.addr, nil
	case <-pc.closeCh:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo 把一个下行 KCP 包投到 addr 对应会话的响应队列。
func (pc *meekServerPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	pc.mu.Lock()
	s := pc.sess[addr.String()]
	pc.mu.Unlock()
	if s == nil {
		return len(p), nil // 未知会话,丢弃(不阻塞 KCP)
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case s.outCh <- cp:
	case <-pc.closeCh:
	default: // 队满丢弃(KCP 会重传)
	}
	return len(p), nil
}

func (pc *meekServerPacketConn) Close() error {
	pc.closeOnce.Do(func() { close(pc.closeCh) })
	return nil
}

func (pc *meekServerPacketConn) LocalAddr() net.Addr                { return pc.local }
func (pc *meekServerPacketConn) SetDeadline(time.Time) error      { return nil }
func (pc *meekServerPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (pc *meekServerPacketConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.PacketConn = (*meekServerPacketConn)(nil)

func (pc *meekServerPacketConn) reaper() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			cut := time.Now().Add(-sessionIdle)
			pc.mu.Lock()
			for id, s := range pc.sess {
				if s.last.Before(cut) {
					delete(pc.sess, id)
				}
			}
			pc.mu.Unlock()
		case <-pc.closeCh:
			return
		}
	}
}
