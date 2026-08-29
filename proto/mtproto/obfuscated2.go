package mtproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"slices"
)

// obfuscated2 —— MTProto 的内层混淆(Telegram "obfuscated2"/Secure 传输)。
//
// 64 字节握手帧布局(偏移/长度):
//
//	[0:8)   noise(随机前缀,受反探测前缀约束)
//	[8:40)  AES key 料(32B)
//	[40:56) AES IV(16B)
//	[56:60) connection type,必须 dd dd dd dd(Secure/PaddedIntermediate)
//	[60:62) DC 索引(小端 int16,取绝对值;0 → 默认 DC)
//	[62:64) noise
//
// 密钥派生:key = SHA256(frame[8:40] ‖ secret16),iv = frame[40:56]。
// 两个方向:recv 用【原始帧】派生;send 用【revert 后的帧】派生(revert = 逆序 [8:56))。
// 线上帧 = 密文 noise + 【明文】key/iv + 密文 connType/dc —— 客户端加密整帧后再把 [8:56)
// 用原始明文覆写,故服务端能先取明文 key/iv 再解密其余部分。
// 没有独立 MAC:解密后 [56:60) 必须等于 dd dd dd dd,这一条同时验证了 secret 正确性。

const (
	hfLen                 = 64
	hfOffsetKey           = 8
	hfLenKey              = 32
	hfOffsetIV            = hfOffsetKey + hfLenKey // 40
	hfLenIV               = 16
	hfOffsetConnType      = hfOffsetIV + hfLenIV // 56
	hfLenConnType         = 4
	hfOffsetDC            = hfOffsetConnType + hfLenConnType // 60
	obfsSecretKeyLen      = 16
	defaultDC             = 2
	maxHandshakeGenRounds = 64
)

// hfConnectionType 是唯一支持的 connection type(Secure / PaddedIntermediate)。
var hfConnectionType = [hfLenConnType]byte{0xdd, 0xdd, 0xdd, 0xdd}

var (
	errBadConnType   = errors.New("mtproto: 不支持的 connection type(secret 不符或非 MTProto 流量)")
	errProbeDetected = errors.New("mtproto: 握手帧命中禁止前缀(疑似探测流量)")
)

// forbiddenPrefixes 是禁止出现在帧首 4 字节的小端 uint32 —— 用于与明文协议/TLS 区分,
// 命中即非 obfuscated2 流量(HTTP 方法、TLS 记录头、其它传输标记)。
var forbiddenPrefixes = [...]uint32{
	0x44414548, // "HEAD"
	0x54534f50, // "POST"
	0x20544547, // "GET "
	0x4954504f, // "OPTI"
	0x02010316, // TLS 记录:16 03 01 02
	0xdddddddd, // PaddedIntermediate 头
	0xeeeeeeee, // Intermediate 头
}

// handshakeFrame 是 64 字节握手帧。
type handshakeFrame struct{ data [hfLen]byte }

func (h *handshakeFrame) key() []byte      { return h.data[hfOffsetKey:hfOffsetIV] }
func (h *handshakeFrame) iv() []byte       { return h.data[hfOffsetIV:hfOffsetConnType] }
func (h *handshakeFrame) connType() []byte { return h.data[hfOffsetConnType:hfOffsetDC] }

// revert 逆序 [8:56)(key 与 iv 合起来的 48 字节),用于派生反方向的 key/iv。
func (h *handshakeFrame) revert() { slices.Reverse(h.data[hfOffsetKey:hfOffsetConnType]) }

// dc 取 DC 索引:小端 int16,负数取绝对值,0 回落默认 DC。
func (h *handshakeFrame) dc() int {
	idx := int16(binary.LittleEndian.Uint16(h.data[hfOffsetDC : hfOffsetDC+2]))
	switch {
	case idx > 0:
		return int(idx)
	case idx < 0:
		return -int(idx)
	}
	return defaultDC
}

// badPrefix 判定帧首是否命中反探测约束(首字节 0xef / 禁止前缀 / [4:8) 全零)。
func badPrefix(d []byte) bool {
	if d[0] == 0xef {
		return true
	}
	if slices.Contains(forbiddenPrefixes[:], binary.LittleEndian.Uint32(d[:4])) {
		return true
	}
	return d[4]|d[5]|d[6]|d[7] == 0
}

// generateHandshake 造一个满足反探测约束的随机握手帧,并写入 connType 与 DC 索引。
func generateHandshake(dc int) (*handshakeFrame, error) {
	h := &handshakeFrame{}
	for range maxHandshakeGenRounds {
		if _, err := io.ReadFull(rand.Reader, h.data[:]); err != nil {
			return nil, err
		}
		if !badPrefix(h.data[:]) {
			copy(h.connType(), hfConnectionType[:])
			binary.LittleEndian.PutUint16(h.data[hfOffsetDC:hfOffsetDC+2], uint16(int16(dc)))
			return h, nil
		}
	}
	return nil, errors.New("mtproto: 生成握手帧多次命中禁止前缀(不应发生)")
}

// deriveCipher 从帧的 key/iv 与 secret 派生 AES-256-CTR 流:key = SHA256(frame[8:40] ‖ secret)。
func deriveCipher(h *handshakeFrame, secret []byte) cipher.Stream {
	sum := sha256.Sum256(append(append(make([]byte, 0, hfLenKey+len(secret)), h.key()...), secret...))
	block, err := aes.NewCipher(sum[:])
	if err != nil { // key 恒为 32 字节,不可能失败
		panic("mtproto: aes.NewCipher: " + err.Error())
	}
	return cipher.NewCTR(block, h.iv())
}

// obfsConn 把一条流包成 obfuscated2 连接:读解密、写加密,CTR 流连续不重置。
type obfsConn struct {
	rw   io.ReadWriter
	recv cipher.Stream
	send cipher.Stream
}

func (c *obfsConn) Read(p []byte) (int, error) {
	n, err := c.rw.Read(p)
	if n > 0 {
		c.recv.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (c *obfsConn) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	c.send.XORKeyStream(buf, p)
	return c.rw.Write(buf)
}

// readObfuscatedHandshake 是服务端侧:读 64 字节帧,派生双向 CTR,校验 connType,返回 DC 索引。
func readObfuscatedHandshake(r io.ReadWriter, secret []byte) (*obfsConn, int, error) {
	var frame handshakeFrame
	if _, err := io.ReadFull(r, frame.data[:]); err != nil {
		return nil, 0, err
	}
	if badPrefix(frame.data[:]) {
		return nil, 0, errProbeDetected
	}
	recv := deriveCipher(&frame, secret) // 用原始帧派生
	frame.revert()
	send := deriveCipher(&frame, secret) // 用 revert 后的帧派生

	// 就地解密整帧(revert 只动 [8:56),connType/dc 位置不受影响)。
	recv.XORKeyStream(frame.data[:], frame.data[:])
	if subtle.ConstantTimeCompare(frame.connType(), hfConnectionType[:]) != 1 {
		return nil, 0, errBadConnType
	}
	return &obfsConn{rw: r, recv: recv, send: send}, frame.dc(), nil
}

// sendObfuscatedHandshake 是客户端侧:造帧、派生双向 CTR、加密整帧后把 [8:56) 覆写回明文再发出。
func sendObfuscatedHandshake(w io.ReadWriter, secret []byte, dc int) (*obfsConn, error) {
	frame, err := generateHandshake(dc)
	if err != nil {
		return nil, err
	}
	orig := *frame // 保留明文 key/iv

	send := deriveCipher(frame, secret) // 用原始帧派生
	frame.revert()
	recv := deriveCipher(frame, secret) // 用 revert 后的帧派生

	send.XORKeyStream(frame.data[:], frame.data[:])
	copy(frame.key(), orig.key()) // [8:40) 覆写回明文
	copy(frame.iv(), orig.iv())   // [40:56) 覆写回明文
	if _, err := w.Write(frame.data[:]); err != nil {
		return nil, err
	}
	return &obfsConn{rw: w, recv: recv, send: send}, nil
}
