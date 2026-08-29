package tlsmirror

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// features 是可选抗检测层开关(padding / 序列水印),两端须一致。
type features struct {
	padding   bool
	watermark bool
}

var (
	errNotReady         = errors.New("tlsmirror: handshake random is not ready")
	errCarrierHandshake = errors.New("tlsmirror: carrier handshake failed")
)

// Conn 是隐蔽隧道端点(net.Conn):Write 把明文封成隐蔽 app-data 记录插进镜像流;Read 取镜像层试解出的
// 隐蔽载荷。加解密密钥在两端 random 就绪后惰性派生(方向标签 :c2s/:s2c)。
type Conn struct {
	ctx    context.Context
	cancel context.CancelFunc

	mirror *mirrorConn

	primaryKey []byte
	isServer   bool

	feat            features
	mu              sync.Mutex
	readMu          sync.Mutex
	writeMu         sync.Mutex
	encryptor       *encryptor
	decryptor       *decryptor
	protocolVersion [2]byte
	firstWrite      bool
	watermarkTx     cipher.Stream
	watermarkRx     cipher.Stream

	readCh        chan []byte
	readBuffer    *bytes.Buffer
	readDeadline  pipeDeadline
	writeDeadline pipeDeadline
}

func newHiddenConn(ctx context.Context, mirror *mirrorConn, primaryKey []byte, isServer bool, feat features) *Conn {
	cctx, cancel := context.WithCancel(ctx)
	return &Conn{
		ctx:           cctx,
		cancel:        cancel,
		mirror:        mirror,
		primaryKey:    primaryKey,
		isServer:      isServer,
		feat:          feat,
		firstWrite:    true,
		readCh:        make(chan []byte, 32),
		readDeadline:  makePipeDeadline(),
		writeDeadline: makePipeDeadline(),
	}
}

// ensureCryptoLocked 惰性派生收发 AEAD(需两端 random 均就绪)。客户端发 :c2s / 收 :s2c;服务端相反。
func (c *Conn) ensureCryptoLocked(version [2]byte) error {
	if c.encryptor != nil && c.decryptor != nil {
		return nil
	}
	clientRandom, serverRandom, err := c.mirror.handshakeRandom()
	if err != nil {
		return err
	}
	encryptTag, decryptTag := ":c2s", ":s2c"
	if c.isServer {
		encryptTag, decryptTag = ":s2c", ":c2s"
	}
	encKey, encMask, err := deriveEncryptionKey(c.primaryKey, clientRandom, serverRandom, encryptTag)
	if err != nil {
		return err
	}
	decKey, decMask, err := deriveEncryptionKey(c.primaryKey, clientRandom, serverRandom, decryptTag)
	if err != nil {
		return err
	}
	if c.encryptor, err = newEncryptor(encKey, encMask); err != nil {
		return err
	}
	if c.decryptor, err = newDecryptor(decKey, decMask); err != nil {
		return err
	}
	c.protocolVersion = version
	if c.protocolVersion == [2]byte{} {
		c.protocolVersion = [2]byte{0x03, 0x03}
	}
	return nil
}

// handleInboundRecord 是镜像层的收隐蔽回调:先(若启用)反序列水印,对 app-data 记录试解密,成功即取出
// 载荷(必要时剥填充)并丢弃(不转发对端)。
func (c *Conn) handleInboundRecord(rec *record) (bool, error) {
	if err := c.applySequenceWatermarkRx(rec); err != nil {
		return false, err
	}
	if rec.recordType != recordTypeApplicationData {
		return false, nil
	}
	c.mu.Lock()
	err := c.ensureCryptoLocked(rec.version)
	dec := c.decryptor
	c.mu.Unlock()
	if err != nil {
		return false, nil
	}
	overhead := c.mirror.explicitNonceOverhead()
	if len(rec.fragment) < overhead+dec.NonceSize() {
		return false, nil
	}
	payload, err := dec.Open(nil, rec.fragment[overhead:])
	if err != nil {
		return false, nil
	}
	c.initSequenceWatermarkRx()
	if c.feat.padding {
		payload, _ = unpackPadding(payload)
		if payload == nil {
			return true, nil
		}
	}
	select {
	case <-c.ctx.Done():
		return true, c.ctx.Err()
	case c.readCh <- payload:
		return true, nil
	}
}

// handleOutboundRecordTx 是镜像层的发隐蔽回调:(若启用)对出向 app-data/alert 记录尾 16B 打序列水印;
// 首条插入的隐蔽记录触发 Tx 水印流初始化(其自身不打,与 mihomo 一致)。
func (c *Conn) handleOutboundRecordTx(rec *record) (bool, error) {
	if !c.feat.watermark {
		return false, nil
	}
	if c.watermarkTx != nil {
		if (rec.recordType == recordTypeApplicationData || rec.recordType == recordTypeAlert) && len(rec.fragment) >= 16 {
			region := rec.fragment[len(rec.fragment)-16:]
			c.watermarkTx.XORKeyStream(region, region)
		}
	}
	if rec.inserted && c.watermarkTx == nil {
		if err := c.initSequenceWatermarkTx(); err != nil {
			return true, nil
		}
	}
	return false, nil
}

// applySequenceWatermarkRx 对收到的 app-data/alert 记录尾 16B 反水印(还原,供后续试解密/转发)。
func (c *Conn) applySequenceWatermarkRx(rec *record) error {
	if !c.feat.watermark || c.watermarkRx == nil {
		return nil
	}
	if rec.recordType != recordTypeApplicationData && rec.recordType != recordTypeAlert {
		return nil
	}
	if len(rec.fragment) < 16 {
		return nil
	}
	region := rec.fragment[len(rec.fragment)-16:]
	c.watermarkRx.XORKeyStream(region, region)
	return nil
}

// initSequenceWatermarkTx 惰性建 Tx 水印流。客户端发向 :c2s、服务端 :s2c(与收方 Rx 标签对齐)。
func (c *Conn) initSequenceWatermarkTx() error {
	clientRandom, serverRandom, err := c.mirror.handshakeRandom()
	if err != nil {
		return err
	}
	tag := ":c2s"
	if c.isServer {
		tag = ":s2c"
	}
	c.watermarkTx, err = newSequenceWatermark(c.primaryKey, clientRandom, serverRandom, tag)
	return err
}

// initSequenceWatermarkRx 惰性建 Rx 水印流(首条隐蔽记录解出后)。标签与对端 Tx 相反方向对齐。
func (c *Conn) initSequenceWatermarkRx() {
	if !c.feat.watermark || c.watermarkRx != nil {
		return
	}
	clientRandom, serverRandom, err := c.mirror.handshakeRandom()
	if err != nil {
		return
	}
	tag := ":s2c"
	if c.isServer {
		tag = ":c2s"
	}
	c.watermarkRx, _ = newSequenceWatermark(c.primaryKey, clientRandom, serverRandom, tag)
}

func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.readBuffer != nil {
			n, _ := c.readBuffer.Read(b)
			if n > 0 {
				return n, nil
			}
			c.readBuffer = nil
		}
		select {
		case <-c.ctx.Done():
			return 0, c.ctx.Err()
		case <-c.mirror.ctx.Done():
			return 0, c.mirror.ctx.Err()
		case <-c.readDeadline.wait():
			return 0, os.ErrDeadlineExceeded
		case data := <-c.readCh:
			c.readBuffer = bytes.NewBuffer(data)
		}
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	writeDeadline := c.writeDeadline.wait()
	if err := c.waitWriteReady(writeDeadline); err != nil {
		return 0, err
	}
	c.firstWrite = false

	c.mu.Lock()
	if err := c.ensureCryptoLocked(c.protocolVersion); err != nil {
		c.mu.Unlock()
		return 0, err
	}
	enc := c.encryptor
	version := c.protocolVersion
	c.mu.Unlock()

	overhead := c.mirror.explicitNonceOverhead()
	maxPlaintext := maxTLSRecordPayload - overhead - enc.Overhead()
	if c.feat.padding {
		maxPlaintext -= 4 // 填充尾部 4B 原长
	}
	if maxPlaintext <= 0 {
		return 0, errors.New("tlsmirror: invalid tls record overhead")
	}
	for written := 0; written < len(b); {
		end := written + maxPlaintext
		if end > len(b) {
			end = len(b)
		}
		plain := b[written:end]
		if c.feat.padding {
			plain = packPadding(append([]byte(nil), plain...), 0)
		}
		fragment := make([]byte, overhead, overhead+len(plain)+enc.Overhead())
		fragment = enc.Seal(fragment, plain)
		rec := &record{
			recordType: recordTypeApplicationData,
			version:    version,
			fragment:   fragment,
			inserted:   true,
		}
		var err error
		if c.isServer {
			err = c.insertS2C(rec, writeDeadline)
		} else {
			err = c.insertC2S(rec, writeDeadline)
		}
		if err != nil {
			return written, err
		}
		written = end
	}
	return len(b), nil
}

// waitWriteReady 等出向就绪(载体握手已产出首条 app-data 记录,门才开),隐蔽记录才能插入。
func (c *Conn) waitWriteReady(deadline <-chan struct{}) error {
	ready := c.mirror.c2sReady
	if c.isServer {
		ready = c.mirror.s2cReady
	}
	select {
	case <-ready:
		return nil
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-c.mirror.ctx.Done():
		return c.mirror.ctx.Err()
	case <-deadline:
		return os.ErrDeadlineExceeded
	}
}

func (c *Conn) insertC2S(rec *record, deadline <-chan struct{}) error {
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-c.mirror.ctx.Done():
		return c.mirror.ctx.Err()
	case <-deadline:
		return os.ErrDeadlineExceeded
	case c.mirror.c2sInsert <- writeTask{rec: duplicateRecord(rec)}:
		return nil
	}
}

func (c *Conn) insertS2C(rec *record, deadline <-chan struct{}) error {
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-c.mirror.ctx.Done():
		return c.mirror.ctx.Err()
	case <-deadline:
		return os.ErrDeadlineExceeded
	case c.mirror.s2cInsert <- writeTask{rec: duplicateRecord(rec)}:
		return nil
	}
}

func (c *Conn) Close() error {
	c.cancel()
	return c.mirror.Close()
}

func (c *Conn) addrConn() net.Conn {
	if c.isServer {
		return c.mirror.clientConn
	}
	return c.mirror.serverConn
}

func (c *Conn) LocalAddr() net.Addr  { return c.addrConn().LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.addrConn().RemoteAddr() }

func (c *Conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *Conn) SetReadDeadline(t time.Time) error  { c.readDeadline.set(t); return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { c.writeDeadline.set(t); return nil }

var _ net.Conn = (*Conn)(nil)

// pipeDeadline 是可重设的截止器(承 net.pipeDeadline 语义):wait() 返回的 chan 在截止时刻 close。
type pipeDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func makePipeDeadline() pipeDeadline { return pipeDeadline{cancel: make(chan struct{})} }

func (d *pipeDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // 定时器已触发,等其 close 完成
	}
	d.timer = nil
	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		c := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(c) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *pipeDeadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
