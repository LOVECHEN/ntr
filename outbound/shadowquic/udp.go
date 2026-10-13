package shadowquic

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	jlsquic "github.com/metacubex/jls-quic-go"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

// ShadowQUIC UDP 线格式(对齐 mihomo transport/shadowquic,禁改):
//
//	关联   = 一条双向流,首段 [cmd 0x03 datagram | 0x04 stream][socks5.Addr](客户端写 0.0.0.0:0,服务端忽略),
//	         此后该流两方向都是【控制流】。
//	控制   = [socks5.Addr][id u16 BE]:发送方首次往某地址发包前,用自己(每连接一套)分配的 id 宣告「id ↔ 地址」;
//	         接收方据此把该 id 的数据归到此关联、并以该地址作为来源/目标。两方向 id 各自独立。
//	数据   = 0x03:QUIC datagram [id u16][payload](不分片,超 datagram 上限即失败);
//	         0x04:每个 (关联, 地址) 一条单向流 [id u16] 后接反复的 [len u16][payload]。
//	控制先于数据不保证:datagram 在映射到来前每 id 最多暂存 32 个;单向流读到 id 后阻塞等映射。
const (
	cmdAssociateDatagram byte = 0x03
	cmdAssociateStream   byte = 0x04

	maxUDPPayload   = 0xffff
	assocQueue      = 128
	maxPendingPerID = 32
)

var (
	errPacketTooLarge = errors.New("shadowquic: UDP 包过大")
	errTooManyIDs     = errors.New("shadowquic: UDP 会话 id 耗尽")
)

type inPacket struct {
	data []byte
	from addr.Socksaddr
}

// connUDP 是一条 QUIC 连接上的 UDP 收发状态(客户端与服务端共用):本端 send-id 分配 + 对端 id → 关联映射,
// 以及该连接唯一的 datagram 读环与单向流接收环。
type connUDP struct {
	conn *jlsquic.Conn
	ctx  context.Context

	mu      sync.Mutex
	nextID  uint16
	sending map[uint16]struct{}
	recv    map[uint16]*recvSlot
}

type recvSlot struct {
	ready   chan struct{} // 映射到来时关闭
	a       *assoc
	from    addr.Socksaddr
	pending [][]byte
}

func newConnUDP(conn *jlsquic.Conn) *connUDP {
	c := &connUDP{conn: conn, ctx: conn.Context(), sending: map[uint16]struct{}{}, recv: map[uint16]*recvSlot{}}
	go c.readDatagrams()
	go c.acceptUni()
	return c
}

func (c *connUDP) readDatagrams() {
	for {
		msg, err := c.conn.ReceiveDatagram(c.ctx)
		if err != nil {
			return
		}
		if len(msg) < 2 {
			continue
		}
		c.feed(binary.BigEndian.Uint16(msg), msg[2:])
	}
}

// feed 把一个 datagram 交给其 id 已映射的关联;映射未到则暂存(有上限)。
func (c *connUDP) feed(id uint16, payload []byte) {
	c.mu.Lock()
	s := c.slot(id)
	if s.a != nil {
		a, from := s.a, s.from
		c.mu.Unlock()
		a.deliver(inPacket{data: payload, from: from})
		return
	}
	if len(s.pending) < maxPendingPerID {
		s.pending = append(s.pending, payload)
	}
	c.mu.Unlock()
}

func (c *connUDP) acceptUni() {
	for {
		rs, err := c.conn.AcceptUniStream(c.ctx)
		if err != nil {
			return
		}
		go c.readUni(rs)
	}
}

// readUni 读一条 stream 模式的单向流:[id] 后反复 [len][payload],映射未到先等。
func (c *connUDP) readUni(rs *jlsquic.ReceiveStream) {
	defer rs.CancelRead(0)
	var hdr [2]byte
	if _, err := io.ReadFull(rs, hdr[:]); err != nil {
		return
	}
	a, from, ok := c.waitBound(binary.BigEndian.Uint16(hdr[:]))
	if !ok {
		return
	}
	for {
		if _, err := io.ReadFull(rs, hdr[:]); err != nil {
			return
		}
		p := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(rs, p); err != nil {
			return
		}
		a.deliver(inPacket{data: p, from: from})
	}
}

// slot 取/建 id 的接收槽(调用方持 c.mu)。
func (c *connUDP) slot(id uint16) *recvSlot {
	s := c.recv[id]
	if s == nil {
		s = &recvSlot{ready: make(chan struct{})}
		c.recv[id] = s
	}
	return s
}

func (c *connUDP) waitBound(id uint16) (*assoc, addr.Socksaddr, bool) {
	c.mu.Lock()
	s := c.slot(id)
	ready := s.ready
	c.mu.Unlock()
	select {
	case <-ready:
	case <-c.ctx.Done():
		return nil, addr.Socksaddr{}, false
	}
	c.mu.Lock()
	a, from := s.a, s.from
	c.mu.Unlock()
	return a, from, a != nil
}

// bind 记录对端宣告的「id ↔ 地址」归属于关联 a,并冲刷该 id 先到的暂存包。
func (c *connUDP) bind(id uint16, a *assoc, from addr.Socksaddr) {
	c.mu.Lock()
	s := c.slot(id)
	first := s.a == nil
	s.a, s.from = a, from
	pending := s.pending
	s.pending = nil
	if first {
		close(s.ready)
	}
	c.mu.Unlock()
	for _, p := range pending {
		a.deliver(inPacket{data: p, from: from})
	}
}

func (c *connUDP) unbind(a *assoc, ids map[uint16]struct{}) {
	c.mu.Lock()
	for id := range ids {
		if s := c.recv[id]; s != nil && s.a == a {
			delete(c.recv, id)
		}
	}
	c.mu.Unlock()
}

func (c *connUDP) allocID() (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for range 1 << 16 {
		id := c.nextID
		c.nextID++
		if _, used := c.sending[id]; !used {
			c.sending[id] = struct{}{}
			return id, nil
		}
	}
	return 0, errTooManyIDs
}

func (c *connUDP) freeIDs(ids map[string]uint16) {
	c.mu.Lock()
	for _, id := range ids {
		delete(c.sending, id)
	}
	c.mu.Unlock()
}

// assoc 是一个 UDP 关联(一条控制流),以多目标 link.PacketConn 交出:客户端出站 DialPacket 与服务端入站
// (交运行时 PacketDispatch)共用。
type assoc struct {
	cu     *connUDP
	ctl    *jlsquic.Stream
	mode   byte // cmdAssociateDatagram | cmdAssociateStream
	remote net.Addr

	in     chan inPacket
	closed chan struct{}
	once   sync.Once

	mu      sync.Mutex // 守发送侧状态与控制流写
	sendID  map[string]uint16
	uni     map[string]*jlsquic.SendStream
	recvIDs map[uint16]struct{}

	dmu      sync.Mutex
	deadline time.Time
}

var _ link.PacketConn = (*assoc)(nil)

func newAssoc(cu *connUDP, ctl *jlsquic.Stream, mode byte, remote net.Addr) *assoc {
	a := &assoc{
		cu: cu, ctl: ctl, mode: mode, remote: remote,
		in: make(chan inPacket, assocQueue), closed: make(chan struct{}),
		sendID: map[string]uint16{}, uni: map[string]*jlsquic.SendStream{}, recvIDs: map[uint16]struct{}{},
	}
	go a.readControl()
	go func() {
		select {
		case <-cu.ctx.Done():
			_ = a.Close()
		case <-a.closed:
		}
	}()
	return a
}

// readControl 读对端的控制消息 [socks5.Addr][id],登记映射;控制流断即关联结束。
func (a *assoc) readControl() {
	defer a.Close()
	var idb [2]byte
	for {
		from, err := readSocksAddr(a.ctl)
		if err != nil {
			return
		}
		if _, err := io.ReadFull(a.ctl, idb[:]); err != nil {
			return
		}
		id := binary.BigEndian.Uint16(idb[:])
		a.mu.Lock()
		a.recvIDs[id] = struct{}{}
		a.mu.Unlock()
		a.cu.bind(id, a, from)
	}
}

func (a *assoc) deliver(p inPacket) {
	select {
	case a.in <- p:
	case <-a.closed:
	default: // 队列满丢包(UDP 语义)
	}
}

func (a *assoc) ReadPacket(b *buf.Buffer) (addr.Socksaddr, error) {
	a.dmu.Lock()
	d := a.deadline
	a.dmu.Unlock()
	var timeout <-chan time.Time
	if !d.IsZero() {
		t := time.NewTimer(time.Until(d))
		defer t.Stop()
		timeout = t.C
	}
	for {
		select {
		case p := <-a.in:
			if len(p.data) > b.Tailroom() {
				continue // 超缓冲丢弃(保包边界)
			}
			copy(b.ExtendTail(len(p.data)), p.data)
			return p.from, nil
		case <-a.closed:
			return addr.Socksaddr{}, net.ErrClosed
		case <-timeout:
			return addr.Socksaddr{}, os.ErrDeadlineExceeded
		}
	}
}

func (a *assoc) WritePacket(b *buf.Buffer, dst addr.Socksaddr) error {
	payload := b.Bytes()
	if len(payload) > maxUDPPayload {
		return errPacketTooLarge
	}
	key, err := encodeSocksAddr(dst)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	select {
	case <-a.closed:
		return net.ErrClosed
	default:
	}
	id, ok := a.sendID[string(key)]
	if !ok {
		if id, err = a.cu.allocID(); err != nil {
			return err
		}
		if _, err = a.ctl.Write(binary.BigEndian.AppendUint16(key, id)); err != nil {
			a.cu.freeIDs(map[string]uint16{"": id})
			return err
		}
		a.sendID[string(key)] = id
	}
	if a.mode == cmdAssociateStream {
		s := a.uni[string(key)]
		if s == nil {
			if s, err = a.cu.conn.OpenUniStreamSync(a.cu.ctx); err != nil {
				return err
			}
			if _, err = s.Write(binary.BigEndian.AppendUint16(nil, id)); err != nil {
				_ = s.Close()
				return err
			}
			a.uni[string(key)] = s
		}
		frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(payload)), uint16(len(payload)))
		_, err = s.Write(append(frame, payload...))
		return err
	}
	pkt := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(payload)), id)
	return a.cu.conn.SendDatagram(append(pkt, payload...))
}

func (a *assoc) Close() error {
	a.once.Do(func() {
		close(a.closed)
		a.ctl.CancelRead(0)
		_ = a.ctl.Close()
		a.mu.Lock()
		for _, s := range a.uni {
			_ = s.Close()
		}
		sent, recvd := a.sendID, a.recvIDs
		a.mu.Unlock()
		a.cu.freeIDs(sent)
		a.cu.unbind(a, recvd)
	})
	return nil
}

func (a *assoc) LocalAddr() net.Addr  { return a.cu.conn.LocalAddr() }
func (a *assoc) RemoteAddr() net.Addr { return a.remote }
func (a *assoc) SetDeadline(t time.Time) error {
	a.dmu.Lock()
	a.deadline = t
	a.dmu.Unlock()
	return nil
}
func (a *assoc) Unwrap() any { return nil }

// writeAssociateRequest 写关联请求 [cmd][0.0.0.0:0](客户端侧;对齐 mihomo 的 UnspecifiedAddr)。
func writeAssociateRequest(w io.Writer, mode byte) error {
	_, err := w.Write([]byte{mode, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
