package muxcool

import (
	"io"
	"net"
	"sync"
)

// InternalDomain —— 反向代理控制子流的目标域(Xray app/reverse/reverse.go:15 硬编码)。
// Bridge 靠它把"控制流"从"用户数据流"里区分出来。
const InternalDomain = "reverse"

// CarrierFqdn / CarrierPort —— Xray Mux.cool 载体连接的固定魔术目标(common/mux/mux.go)。
// 常规 mux(非反连):载体协议(vless/vmess/trojan/ss)拨到这里,其上跑 Mux.cool 帧。
// vless/vmess 用 Command=Mux(0x03,线上不带地址)表达,由协议层翻译成此规范目标,使运行时
// 的载体识别保持"看地址"的协议无关形态;trojan/ss 直接在线上带此地址。
const (
	CarrierFqdn        = "v1.mux.cool"
	CarrierPort uint16 = 9527
)

// maxServerSessions —— 单条隧道并发子流硬上限。防被攻陷/异常 Portal 无限发 New 帧,
// 把 Bridge 的 fd/内存/goroutine 打满(每子流 = 一条落地 socket + goroutine + 64KiB 缓冲)。
const maxServerSessions = 512

// maxUDPPending —— UDP 子流在异步拨号完成前暂存的数据报上限(保数据报边界,不能用字节流
// bufPipe;超上限丢弃,UDP 语义可丢)。防拨号未就绪期间的 Keep 数据报被丢(竞态)。
const maxUDPPending = 64

// Dispatcher —— Bridge 收到用户数据子流后,如何拨到本地目标。
// 由上层(reverse.Bridge)注入:通常接到 NTR direct 出站,落地到 Bridge 所在内网。
type Dispatcher interface {
	// DialTarget 按 target 拨一条到本地目标的双工连接。
	DialTarget(network TargetNetwork, addr Address, port uint16) (net.Conn, error)
}

// ServerWorker —— 在一条(VLESS-Rvs 隧道解出的)明文流上跑 Mux.cool 服务端。
//
// 角色反转:Bridge 主动拨号建隧道,但在 Mux.cool 里是服务端——被动读 Portal 开来的
// New 帧、把子流落地、回写 Keep/End。永不主动开子流、永不回写控制心跳。
type ServerWorker struct {
	link       io.ReadWriteCloser
	dispatcher Dispatcher
	onControl  func(payload []byte) // 控制子流每个数据帧回调(解 Control 心跳);可 nil

	writeMu  sync.Mutex // 串行化所有帧写(多个子流 goroutine 并发回写)
	mu       sync.Mutex
	sessions map[uint16]*serverSession
}

type serverSession struct {
	id      uint16
	control bool
	udp     bool // UDP 子流:每帧=一个数据报,直写 conn(不经 bufPipe,保数据报边界)

	// conn 由异步 land goroutine 拨号成功后填入;finished 标记子流已收尾。
	// udpPending:UDP 子流在拨号完成前暂存的数据报(TCP 用 inW 字节流暂存,UDP 须保边界)。
	// smu 保护 conn/finished/udpPending(读环/handleEnd/closeAll 与 land goroutine 并发访问)。
	smu        sync.Mutex
	conn       net.Conn
	finished   bool
	udpPending [][]byte

	inW  *bufPipe // 仅 TCP:reader loop 把上行数据写这里 → 由 goroutine 拷到 conn
	once sync.Once
}

// setConn 在异步落地拨号成功后设置 conn(TCP 用);若子流已收尾(finish 先到)返回 false,弃 conn。
func (s *serverSession) setConn(c net.Conn) bool {
	s.smu.Lock()
	defer s.smu.Unlock()
	if s.finished {
		return false
	}
	s.conn = c
	return true
}

// activateUDP 拨号成功后原子地设 conn + 取出暂存的数据报(供 landUDP flush)。
// 若已收尾返回 (nil,false),调用方弃 conn。
func (s *serverSession) activateUDP(c net.Conn) ([][]byte, bool) {
	s.smu.Lock()
	defer s.smu.Unlock()
	if s.finished {
		return nil, false
	}
	s.conn = c
	p := s.udpPending
	s.udpPending = nil
	return p, true
}

// deliverUDP 投递一个 UDP 数据报:conn 就绪则直写;拨号未完成则暂存(有上限,超则丢);已收尾则丢。
// 全程持锁,消除"getConn 后 conn 刚就绪"的竞态与拨号前丢包。
func (s *serverSession) deliverUDP(data []byte) {
	s.smu.Lock()
	if s.finished {
		s.smu.Unlock()
		return
	}
	if s.conn != nil {
		c := s.conn
		s.smu.Unlock()
		c.Write(data) // UDP 数据报写通常不阻塞(内核缓冲)
		return
	}
	if len(s.udpPending) < maxUDPPending {
		cp := make([]byte, len(data))
		copy(cp, data)
		s.udpPending = append(s.udpPending, cp)
	}
	s.smu.Unlock()
}

// NewServerWorker 构造。onControl 可为 nil(此时控制子流数据被丢弃,仍正常 drain)。
func NewServerWorker(link io.ReadWriteCloser, d Dispatcher, onControl func([]byte)) *ServerWorker {
	return &ServerWorker{
		link:       link,
		dispatcher: d,
		onControl:  onControl,
		sessions:   make(map[uint16]*serverSession),
	}
}

// Run 跑读环,直到 link 出错/关闭。返回时清理所有子流。
func (w *ServerWorker) Run() error {
	defer w.closeAll()
	for {
		m, data, err := ReadFrame(w.link)
		if err != nil {
			return err
		}
		switch m.Status {
		case StatusNew:
			w.handleNew(m, data)
		case StatusKeep:
			w.handleKeep(m, data)
		case StatusEnd:
			w.handleEnd(m)
		case StatusKeepAlive:
			// 纯心跳,丢弃(Xray 的 Writer 从不主动发,收到即忽略)。
		}
	}
}

// Close 外部主动关停:关所有子流(inW/conn)+ 关 link。用于 ctx 取消时打断——
// 关 link 打断阻塞在 ReadFrame 的读环;关各子流 inW 打断可能卡在 bufPipe.Write 的读环
// (HoL 背压下 Run 停在写而非读,单靠 link.Close 唤不醒)。幂等,可与 Run 的 defer 并发。
func (w *ServerWorker) Close() error {
	w.closeAll()
	return nil
}

// -------- 帧写(均加锁)--------

func (w *ServerWorker) writeData(id uint16, data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return WriteData(w.link, id, data)
}

func (w *ServerWorker) writeEnd(id uint16, hasErr bool) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return WriteEnd(w.link, id, hasErr)
}

// writeUDPData 回写一个 UDP 数据报为 Keep 帧(带 network=UDP + 地址,对齐 Xray UDP 帧)。
func (w *ServerWorker) writeUDPData(id uint16, addr Address, port uint16, data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	m := &FrameMetadata{SessionID: id, Status: StatusKeep, Network: NetworkUDP, Address: addr, Port: port, Option: OptionData}
	return WriteFrame(w.link, m, data)
}

// -------- 会话表 --------

func (w *ServerWorker) addSession(s *serverSession) {
	w.mu.Lock()
	w.sessions[s.id] = s
	w.mu.Unlock()
}

func (w *ServerWorker) getSession(id uint16) *serverSession {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sessions[id]
}

func (w *ServerWorker) removeSession(id uint16) {
	w.mu.Lock()
	delete(w.sessions, id)
	w.mu.Unlock()
}

func (w *ServerWorker) sessionCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.sessions)
}

// finish 幂等收尾:标记 finished、从表移除、(可选)发 End、关 conn/pipe。
// 三条路径可能触发(Portal 发来 End / 本地目标读到 EOF / worker.Close),sync.Once 保证只做一次。
func (w *ServerWorker) finish(s *serverSession, sendEnd bool) {
	s.once.Do(func() {
		s.smu.Lock()
		s.finished = true
		c := s.conn
		s.smu.Unlock()
		w.removeSession(s.id)
		if sendEnd {
			w.writeEnd(s.id, false)
		}
		if s.inW != nil {
			s.inW.Close()
		}
		if c != nil {
			c.Close()
		}
	})
}

func (w *ServerWorker) closeAll() {
	w.mu.Lock()
	all := make([]*serverSession, 0, len(w.sessions))
	for _, s := range w.sessions {
		all = append(all, s)
	}
	w.mu.Unlock()
	for _, s := range all {
		w.finish(s, false)
	}
	w.link.Close()
}

// -------- 帧处理 --------

func (w *ServerWorker) handleNew(m *FrameMetadata, data []byte) {
	// 控制子流:target 域 == "reverse"(UDP, port 0)。不拨号,只消费(极快,同步)。
	if m.Address.IsDomain && m.Address.Domain == InternalDomain {
		w.addSession(&serverSession{id: m.SessionID, control: true})
		if len(data) > 0 && w.onControl != nil {
			w.onControl(data)
		}
		return
	}

	// 重复 id:Portal 不该在活跃 id 上再发 New。若覆盖会挤出旧会话致泄漏,且旧会话收尾时
	// removeSession(id) 会误删新会话表项。→ 拒绝(回带 error 的 End),不覆盖。
	if w.getSession(m.SessionID) != nil {
		w.writeEnd(m.SessionID, true)
		return
	}
	// 会话数硬上限:防被攻陷/异常 Portal 无限开流耗尽 fd/内存/goroutine。
	if w.sessionCount() >= maxServerSessions {
		w.writeEnd(m.SessionID, true)
		return
	}

	// ★DialTarget 移出读环:先同步登记会话(后续 Keep 能找到),拨号 + 双向搬运放异步 goroutine。
	// 否则一个拨不通/黑洞的本地目标会把读环卡在 DialTarget 上,冻结整条隧道的所有子流与控制心跳。
	if m.Network == NetworkUDP {
		s := &serverSession{id: m.SessionID, udp: true}
		w.addSession(s)
		go w.landUDP(s, m.Address, m.Port, data)
		return
	}
	bp := newBufPipe(sessionBufLimit)
	s := &serverSession{id: m.SessionID, inW: bp}
	w.addSession(s)
	if len(data) > 0 {
		bp.Write(data) // 新建空 bufPipe,首包不阻塞
	}
	go w.landTCP(s, m.Address, m.Port)
}

// landTCP 异步拨本地 TCP 目标并双向搬运(读环不阻塞在拨号/黑洞目标)。
func (w *ServerWorker) landTCP(s *serverSession, addr Address, port uint16) {
	conn, err := w.dispatcher.DialTarget(NetworkTCP, addr, port)
	if err != nil {
		w.finish(s, true) // 落地失败:回带 error 的 End 通知 Portal
		return
	}
	if !s.setConn(conn) { // 拨号期间子流已被关(Portal 发 End / worker 关停)→ 弃 conn
		conn.Close()
		return
	}
	// 上行:mux 收到的数据(handleKeep 写入 inW)→ 本地目标。
	go io.Copy(conn, s.inW)
	// 下行:本地目标响应 → mux(Keep 帧);EOF/出错则收尾并发 End。
	buf := make([]byte, StreamChunkSize)
	for {
		n, er := conn.Read(buf)
		if n > 0 {
			if we := w.writeData(s.id, buf[:n]); we != nil {
				break
			}
		}
		if er != nil {
			break
		}
	}
	w.finish(s, true)
}

// landUDP 异步拨本地 UDP 目标(连接式)并按数据报双向搬运。
func (w *ServerWorker) landUDP(s *serverSession, addr Address, port uint16, first []byte) {
	conn, err := w.dispatcher.DialTarget(NetworkUDP, addr, port)
	if err != nil {
		w.finish(s, true)
		return
	}
	pending, ok := s.activateUDP(conn) // 原子:设 conn + 取暂存数据报
	if !ok {
		conn.Close() // 拨号期间子流已被关 → 弃 conn
		return
	}
	if len(first) > 0 {
		conn.Write(first) // New 帧首个数据报
	}
	for _, p := range pending { // flush 拨号完成前暂存的数据报(保序、保边界)
		conn.Write(p)
	}
	buf := make([]byte, 64*1024)
	for {
		n, er := conn.Read(buf)
		if n > 0 {
			if we := w.writeUDPData(s.id, addr, port, buf[:n]); we != nil {
				break
			}
		}
		if er != nil {
			break
		}
	}
	w.finish(s, true)
}

func (w *ServerWorker) handleKeep(m *FrameMetadata, data []byte) {
	s := w.getSession(m.SessionID)
	if s == nil {
		// 未知会话:回 End 通知对端关闭(对齐 Xray server.go:308-311)。
		w.writeEnd(m.SessionID, false)
		return
	}
	if s.control {
		if len(data) > 0 && w.onControl != nil {
			w.onControl(data)
		}
		return
	}
	if s.udp {
		if len(data) > 0 {
			s.deliverUDP(data) // conn 就绪则直写;拨号未完成则暂存(不丢包);已收尾则丢
		}
		return
	}
	if len(data) > 0 && s.inW != nil {
		// 注:此处对 inW 的写在读环内同步进行,bufPipe 满(64KiB 背压)时会阻塞读环——
		// 这是 Mux.cool 单读环的固有队头阻塞(HoL),Xray 亦然(其 buf pipe 16KiB)。
		// worker.Close() 会关 inW 打断此阻塞(供 ctx 取消/关停);单慢子流不冻死整条隧道的
		// 完整解耦(每子流独立写 goroutine + 有界队列)后置。
		s.inW.Write(data)
	}
}

func (w *ServerWorker) handleEnd(m *FrameMetadata) {
	if s := w.getSession(m.SessionID); s != nil {
		w.finish(s, false) // Portal 主动关,不回 End
	}
}
