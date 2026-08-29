package tlsmirror

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"sync"
)

// messageHook 在一条记录经过时回调:drop=true 表示这条被隐蔽层吃掉(不转发对端)。
type messageHook func(*record) (drop bool, err error)

// writeTask 是 recordWriter 的一个写任务:插入一条记录(rec)、或转发原始字节(raw)、或读到底切直拷(fallback)。
type writeTask struct {
	rec      *record
	raw      []byte
	fallback *bufio.Reader
}

// mirrorConn 镜像引擎:在 clientConn(近端/载体客户端)与 serverConn(远端/真后端)之间双向泵 TLS 记录,
// 转发真记录、丢弃并取出隐蔽记录(收)、把隐蔽记录插进同一出向流(发)。
type mirrorConn struct {
	ctx    context.Context
	cancel context.CancelFunc

	clientConn net.Conn
	serverConn net.Conn

	onC2SMessage   messageHook // 收:C2S 方向来的记录(服务端在此取隐蔽)
	onS2CMessage   messageHook // 收:S2C 方向来的记录(客户端在此取隐蔽)
	onC2SMessageTx messageHook // 发:写入 C2S 流前(客户端插隐蔽,recordWriter 内回调)
	onS2CMessageTx messageHook // 发:写入 S2C 流前(服务端插隐蔽)

	c2sInsert chan writeTask
	s2cInsert chan writeTask
	c2sReady  chan struct{}
	s2cReady  chan struct{}
	onClose   func()

	randomMu          sync.RWMutex
	clientRandom      [32]byte
	serverRandom      [32]byte
	clientRandomReady bool
	serverRandomReady bool
	c2sReadyOnce      sync.Once
	s2cReadyOnce      sync.Once

	// TLS1.2 显式 nonce 载体支持(explicitSuites 为空 → 恒 TLS1.3 路径,overhead=0)。
	explicitSuites   map[uint16]struct{}
	explicitReady    chan struct{} // s2cWorker 抓到 ServerHello cipher suite 后关闭
	tls12Explicit    bool
	c2sExplicitNonce explicitNonceGenerator
	s2cExplicitNonce explicitNonceGenerator
}

func newMirrorConn(ctx context.Context, clientConn, serverConn net.Conn, explicitSuites []uint16, onC2S, onS2C, onC2STx, onS2CTx messageHook) *mirrorConn {
	mctx, cancel := context.WithCancel(ctx)
	suites := make(map[uint16]struct{}, len(explicitSuites))
	for _, s := range explicitSuites {
		suites[s] = struct{}{}
	}
	return &mirrorConn{
		ctx:            mctx,
		cancel:         cancel,
		clientConn:     clientConn,
		serverConn:     serverConn,
		onC2SMessage:   onC2S,
		onS2CMessage:   onS2C,
		onC2SMessageTx: onC2STx,
		onS2CMessageTx: onS2CTx,
		c2sInsert:      make(chan writeTask, 100),
		s2cInsert:      make(chan writeTask, 100),
		c2sReady:       make(chan struct{}),
		s2cReady:       make(chan struct{}),
		explicitSuites: suites,
		explicitReady:  make(chan struct{}),
	}
}

func (m *mirrorConn) start() {
	go m.c2sWorker()
	go m.s2cWorker()
	go func() {
		<-m.ctx.Done()
		if m.onClose != nil {
			m.onClose()
		}
		_ = m.clientConn.Close()
		_ = m.serverConn.Close()
	}()
}

func (m *mirrorConn) Close() error {
	m.cancel()
	return nil
}

func (m *mirrorConn) handshakeRandom() ([32]byte, [32]byte, error) {
	m.randomMu.RLock()
	defer m.randomMu.RUnlock()
	if !m.clientRandomReady || !m.serverRandomReady {
		return [32]byte{}, [32]byte{}, errNotReady
	}
	return m.clientRandom, m.serverRandom, nil
}

// explicitNonceOverhead:等 ServerHello 就绪后返回隐蔽记录的前置开销 —— TLS1.2 显式 nonce 载体为 8,否则 0。
func (m *mirrorConn) explicitNonceOverhead() int {
	select {
	case <-m.explicitReady:
	case <-m.ctx.Done():
		return 0
	}
	if m.tls12Explicit {
		return 8
	}
	return 0
}

// InsertC2S 把一条【真】记录排进 C2S 出向队列(转发到 serverConn)。
func (m *mirrorConn) InsertC2S(rec *record) error {
	select {
	case <-m.ctx.Done():
		return m.ctx.Err()
	case m.c2sInsert <- writeTask{rec: duplicateRecord(rec)}:
		return nil
	}
}

// InsertS2C 把一条【真】记录排进 S2C 出向队列(转发到 clientConn)。
func (m *mirrorConn) InsertS2C(rec *record) error {
	select {
	case <-m.ctx.Done():
		return m.ctx.Err()
	case m.s2cInsert <- writeTask{rec: duplicateRecord(rec)}:
		return nil
	}
}

// c2sWorker:近端→远端。抓 ClientHello 的 client random,转发其后的每条记录,并让 onC2SMessage 取隐蔽。
func (m *mirrorConn) c2sWorker() {
	serverWriter := bufio.NewWriterSize(m.serverConn, 65536)

	first, clientReader, firstRaw, err := m.captureFirstHandshakeRecord(m.clientConn, serverWriter)
	if err != nil {
		return
	}
	clientRandom, err := parseClientRandom(first.fragment)
	if err != nil {
		m.fallbackDirectCopy(serverWriter, clientReader, firstRaw)
		return
	}
	m.randomMu.Lock()
	m.clientRandom = clientRandom
	m.clientRandomReady = true
	m.randomMu.Unlock()
	if err := writeRawFlush(serverWriter, firstRaw); err != nil {
		m.cancel()
		return
	}

	go m.recordWriter(serverWriter, m.c2sInsert, m.onC2SMessageTx, true)
	ccsWasLast := false // TLS1.2 显式 nonce:上一条是 CCS,则下一条(加密的 Finished)判首帧就绪
	for m.ctx.Err() == nil {
		rec, raw, err := readRecord(clientReader)
		if err != nil {
			m.fallbackQueuedCopy(m.c2sInsert, clientReader, nil, raw)
			return
		}
		if rec.recordType == recordTypeHandshake && ccsWasLast && !hasZeroExplicitNonce(rec.fragment) {
			m.fallbackQueuedCopy(m.c2sInsert, clientReader, rec, nil)
			return
		}
		if rec.recordType == recordTypeChangeCipherSpec {
			select {
			case <-m.explicitReady:
			default:
				m.fallbackQueuedCopy(m.c2sInsert, clientReader, rec, nil)
				return
			}
		}
		if m.onC2SMessage != nil {
			drop, err := m.onC2SMessage(rec)
			if err != nil {
				m.fallbackQueuedCopy(m.c2sInsert, clientReader, rec, nil)
				return
			}
			if drop {
				continue
			}
		}
		if err := m.InsertC2S(rec); err != nil {
			m.cancel()
			return
		}
		if rec.recordType == recordTypeChangeCipherSpec && m.tls12Explicit {
			ccsWasLast = true
			continue
		}
		if rec.recordType == recordTypeApplicationData || rec.recordType == recordTypeHandshake && ccsWasLast {
			m.c2sReadyOnce.Do(func() { close(m.c2sReady) })
		}
		ccsWasLast = false
	}
}

// s2cWorker:远端→近端。抓 ServerHello 的 server random,转发其后的每条记录,并让 onS2CMessage 取隐蔽。
func (m *mirrorConn) s2cWorker() {
	clientWriter := bufio.NewWriterSize(m.clientConn, 65536)

	first, serverReader, firstRaw, err := m.captureFirstHandshakeRecord(m.serverConn, clientWriter)
	if err != nil {
		return
	}
	serverRandom, cipherSuite, err := parseServerHello(first.fragment)
	if err != nil {
		m.fallbackDirectCopy(clientWriter, serverReader, firstRaw)
		return
	}
	m.randomMu.Lock()
	m.serverRandom = serverRandom
	m.serverRandomReady = true
	_, m.tls12Explicit = m.explicitSuites[cipherSuite]
	m.randomMu.Unlock()
	close(m.explicitReady) // 通告 explicitNonceOverhead:cipher suite 已定
	if m.onS2CMessage != nil {
		if _, err := m.onS2CMessage(first); err != nil {
			m.fallbackDirectCopy(clientWriter, serverReader, firstRaw)
			return
		}
	}
	if err := writeRawFlush(clientWriter, firstRaw); err != nil {
		m.cancel()
		return
	}

	go m.recordWriter(clientWriter, m.s2cInsert, m.onS2CMessageTx, false)
	ccsWasLast := false
	for m.ctx.Err() == nil {
		rec, raw, err := readRecord(serverReader)
		if err != nil {
			m.fallbackQueuedCopy(m.s2cInsert, serverReader, nil, raw)
			return
		}
		if rec.recordType == recordTypeHandshake && ccsWasLast && !hasZeroExplicitNonce(rec.fragment) {
			m.fallbackQueuedCopy(m.s2cInsert, serverReader, rec, nil)
			return
		}
		if m.onS2CMessage != nil {
			drop, err := m.onS2CMessage(rec)
			if err != nil {
				m.fallbackQueuedCopy(m.s2cInsert, serverReader, rec, nil)
				return
			}
			if drop {
				continue
			}
		}
		if err := m.InsertS2C(rec); err != nil {
			m.cancel()
			return
		}
		if rec.recordType == recordTypeChangeCipherSpec && m.tls12Explicit {
			ccsWasLast = true
			continue
		}
		if rec.recordType == recordTypeApplicationData || rec.recordType == recordTypeHandshake && ccsWasLast {
			m.s2cReadyOnce.Do(func() { close(m.s2cReady) })
		}
		ccsWasLast = false
	}
}

// recordWriter 串行化一个方向的出向队列:真记录直写,插入的隐蔽记录经 Tx hook 后写。covert 与 genuine
// 走同一队列 → 同一 TCP 流交织。遇 alert 或 fallback 收尾。
func (m *mirrorConn) recordWriter(writer *bufio.Writer, ch <-chan writeTask, hook messageHook, c2s bool) {
	for m.ctx.Err() == nil {
		select {
		case <-m.ctx.Done():
			return
		case task := <-ch:
			rec := task.rec
			if rec != nil {
				m.fillExplicitNonce(rec, c2s)
				if hook != nil {
					drop, err := hook(rec)
					if err != nil {
						m.cancel()
						return
					}
					if drop {
						continue
					}
				}
				if err := writeRecord(writer, rec); err != nil {
					m.cancel()
					return
				}
				if rec.recordType == recordTypeAlert {
					m.cancel()
					return
				}
			}
			if len(task.raw) > 0 {
				if _, err := writer.Write(task.raw); err != nil {
					m.cancel()
					return
				}
				if err := writer.Flush(); err != nil {
					m.cancel()
					return
				}
			}
			if task.fallback != nil {
				_ = copyFlush(writer, task.fallback)
				m.cancel()
				return
			}
		}
	}
}

// fillExplicitNonce 给插入的隐蔽记录写 TLS1.2 GCM 显式 nonce(仅 tls12Explicit 时;纯伪装,让隐蔽记录像
// 真 TLS1.2 GCM 记录)。recordWriter 独占各方向插入队列,故 nonce 生成器无需额外同步。
func (m *mirrorConn) fillExplicitNonce(rec *record, c2s bool) {
	if !rec.inserted || len(rec.fragment) < 8 {
		return
	}
	select {
	case <-m.explicitReady:
	default:
		return
	}
	if !m.tls12Explicit {
		return
	}
	if rec.recordType != recordTypeApplicationData && rec.recordType != recordTypeAlert {
		return
	}
	nonce := m.s2cExplicitNonce.Next()
	if c2s {
		nonce = m.c2sExplicitNonce.Next()
	}
	copy(rec.fragment[:8], nonce)
}

// captureFirstHandshakeRecord 从 src 读到第一条完整握手记录:非握手起手则直拷兜底(非 TLS 流)。
func (m *mirrorConn) captureFirstHandshakeRecord(src net.Conn, dst *bufio.Writer) (*record, *bufio.Reader, []byte, error) {
	var readBuffer [65536]byte
	var copied int
	for m.ctx.Err() == nil {
		n, err := src.Read(readBuffer[copied:])
		if err != nil {
			m.cancel()
			return nil, nil, nil, err
		}
		buffer := readBuffer[:copied+n]
		rec, needMore, processed, err := peekFirstHandshakeRecord(buffer)
		if processed == 0 {
			if needMore == 0 {
				_, _ = dst.Write(buffer)
				_ = dst.Flush()
				_ = copyFlush(dst, src)
				m.cancel()
				return nil, nil, nil, err
			}
			if _, err := dst.Write(readBuffer[copied : copied+n]); err != nil {
				m.cancel()
				return nil, nil, nil, err
			}
			if err := dst.Flush(); err != nil {
				m.cancel()
				return nil, nil, nil, err
			}
			copied += n
			continue
		}
		raw := append([]byte(nil), readBuffer[copied:processed]...)
		rest := append([]byte(nil), buffer[processed:]...)
		return rec, bufio.NewReaderSize(io.MultiReader(bytes.NewReader(rest), src), 65536), raw, nil
	}
	return nil, nil, nil, m.ctx.Err()
}

// fallbackQueuedCopy:读侧出错/回退时,把剩余流经出向队列直拷到对端(保持透明中继)。
func (m *mirrorConn) fallbackQueuedCopy(ch chan<- writeTask, src *bufio.Reader, first *record, raw []byte) {
	var rec *record
	if first != nil {
		rec = duplicateRecord(first)
	}
	raw = append([]byte(nil), raw...)
	select {
	case <-m.ctx.Done():
	case ch <- writeTask{rec: rec, raw: raw, fallback: src}:
	}
}

// fallbackDirectCopy:非 TLS/解析失败时,直接把 raw + 剩余 src 拷到 writer(不再镜像)。
func (m *mirrorConn) fallbackDirectCopy(writer *bufio.Writer, src *bufio.Reader, raw []byte) {
	if err := writeRawFlush(writer, raw); err != nil {
		m.cancel()
		return
	}
	_ = copyFlush(writer, src)
	m.cancel()
}

func copyFlush(writer *bufio.Writer, src io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, err := writer.Write(buf[:n]); err != nil {
				return err
			}
			if err := writer.Flush(); err != nil {
				return err
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

func writeRawFlush(writer *bufio.Writer, raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	if _, err := writer.Write(raw); err != nil {
		return err
	}
	return writer.Flush()
}
