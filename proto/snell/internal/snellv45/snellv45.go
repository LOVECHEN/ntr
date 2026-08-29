// Package snellv45 实现 Snell 协议 v4 / v5 的线格式(两者解码逐字节一致,仅发送整形不同,
// 不影响对端解码,故合用一套引擎)。加密内核与 v6 相同:Argon2id(原始 PSK, salt, t=3/m=8/p=1)
// → AES-128-GCM + 12B LE nonce。区别全在 framing:v4/v5 用【明文 16B salt】+ 固定 23B 帧头 +
// 仅首块 padding(swapPadding 偶字节 mix)+ 每块 payload 上限 0x3FFF。
//
// 线格式(对齐 mihomo transport/snell/v4.go 与逆向的官方服务端):
//
//	stream = salt(16, 明文) ‖ frame*
//	frame  = headerCipher(23) ‖ [padding(padLen)] ‖ payloadCipher(payLen+16)
//	header(7 明文) = [0x04][00][00][padLen BE16][payLen BE16]
//	padding 仅首个数据帧;swapPadding 把 padding 与 payloadCipher 的偶数位互换。
//	payLen==0 = 零长块(半关标记)。
//
// 命令层与 v6 同:[ver=1][cmd][idLen][clientID][hostLen][host][port BE];服务端首响应
// 前置 0x00 OK 状态字节(0x02=错误)。多用户 = 单端口 PSK + clientID。
package snellv45

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize    = 16
	nonceSize   = 12
	hdrPlain    = 7
	hdrCipher   = hdrPlain + 16 // 23
	maxPayload  = 0x3FFF
	initPadMin  = 0x100 // 256
	initPadSpan = 0x100 // padding ∈ [256,511]
)

var (
	errBadHeader = errors.New("snellv45: bad frame header")
	errTooLarge  = errors.New("snellv45: frame too large")
)

// newAEAD 由 PSK+salt 派生 AES-128-GCM(会话密钥 = Argon2id(psk,salt,3,8,1,32)[:16])。
func newAEAD(psk, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey(psk, salt, 3, 8, 1, 32)[:16]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// incNonce 是 12B 小端计数器自增(与对端逐字节一致)。
func incNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// swapPadding 把 padding 与 payloadCipher 的偶数位互换(自逆)。
func swapPadding(pad, pc []byte) {
	limit := len(pad)
	if len(pc) < limit {
		limit = len(pc)
	}
	for i := 0; i < limit; i += 2 {
		pad[i], pc[i] = pc[i], pad[i]
	}
}

// ---------- Sender ----------

// Sender 编码 v4/v5 帧。首帧带明文 salt + padding。
type Sender struct {
	aead       cipher.AEAD
	nonce      [nonceSize]byte
	salt       [saltSize]byte
	saltSent   bool
	initialPad int
}

// NewSender 造 Sender(自选随机 salt + 首块 padding 长度)。
func NewSender(psk []byte) (*Sender, error) {
	var salt [saltSize]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return nil, err
	}
	aead, err := newAEAD(psk, salt[:])
	if err != nil {
		return nil, err
	}
	d, err := rand.Int(rand.Reader, big.NewInt(initPadSpan))
	if err != nil {
		return nil, err
	}
	return &Sender{aead: aead, salt: salt, initialPad: initPadMin + int(d.Int64())}, nil
}

// EncodeChunk 把任意长 payload 切成 ≤0x3FFF 的帧(首帧带 salt+padding)。空 payload = 零长块。
func (s *Sender) EncodeChunk(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return s.frame(nil, 0)
	}
	var out []byte
	for len(payload) > 0 {
		n := len(payload)
		if n > maxPayload {
			n = maxPayload
		}
		pad := 0
		if !s.saltSent {
			pad = s.initialPad
		}
		f, err := s.frame(payload[:n], pad)
		if err != nil {
			return nil, err
		}
		out = append(out, f...)
		payload = payload[n:]
	}
	return out, nil
}

func (s *Sender) frame(payload []byte, padLen int) ([]byte, error) {
	var hdr [hdrPlain]byte
	hdr[0] = 4
	binary.BigEndian.PutUint16(hdr[3:5], uint16(padLen))
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))
	hc := s.aead.Seal(nil, s.nonce[:], hdr[:], nil)
	incNonce(s.nonce[:])

	var pc []byte
	if len(payload) > 0 {
		pc = s.aead.Seal(nil, s.nonce[:], payload, nil)
		incNonce(s.nonce[:])
	}

	out := make([]byte, 0, saltSize+len(hc)+padLen+len(pc))
	if !s.saltSent {
		out = append(out, s.salt[:]...)
		s.saltSent = true
	}
	out = append(out, hc...)
	if padLen > 0 {
		pad := make([]byte, padLen)
		if _, err := io.ReadFull(rand.Reader, pad); err != nil { // padding 内容任意(收端 un-swap 后丢弃)
			return nil, err
		}
		swapPadding(pad, pc)
		out = append(out, pad...)
	}
	out = append(out, pc...)
	return out, nil
}

// ---------- Receiver ----------

// Receiver 解码 v4/v5 帧。首次读取明文 salt 后建 AEAD。
type Receiver struct {
	psk      []byte
	aead     cipher.AEAD
	nonce    [nonceSize]byte
	saltRead bool
}

// NewReceiver 造 Receiver。
func NewReceiver(psk []byte) *Receiver { return &Receiver{psk: psk} }

// DecodeChunk 解一帧,返回 payload;零长块返回 (nil,nil)。
func (r *Receiver) DecodeChunk(br io.Reader) ([]byte, error) {
	if !r.saltRead {
		var salt [saltSize]byte
		if _, err := io.ReadFull(br, salt[:]); err != nil {
			return nil, err
		}
		aead, err := newAEAD(r.psk, salt[:])
		if err != nil {
			return nil, err
		}
		r.aead = aead
		r.saltRead = true
	}
	var hc [hdrCipher]byte
	if _, err := io.ReadFull(br, hc[:]); err != nil {
		return nil, err
	}
	hdr, err := r.aead.Open(nil, r.nonce[:], hc[:], nil)
	incNonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	if len(hdr) != hdrPlain || hdr[0] != 4 {
		return nil, errBadHeader
	}
	padLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	payLen := int(binary.BigEndian.Uint16(hdr[5:7]))
	if payLen == 0 {
		return nil, nil // 零长块 = 半关
	}
	if payLen > maxPayload || padLen > maxPayload {
		return nil, errTooLarge
	}
	frame := make([]byte, padLen+payLen+16)
	if _, err := io.ReadFull(br, frame); err != nil {
		return nil, err
	}
	if padLen > 0 {
		swapPadding(frame[:padLen], frame[padLen:])
	}
	pc := frame[padLen:]
	payload, err := r.aead.Open(nil, r.nonce[:], pc, nil)
	incNonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	return payload, nil
}
