// Package snellv123 实现 Snell v1/v2/v3 的净室数据面 —— 它们用 shadowsocks-AEAD 分帧(v4/v5/v6 之前的
// 老框架),但 KDF(Argon2id)、命令层(ver=1 + cmd + clientID + host/port + 0x00 状态字节)与 v4/v5/v6
// 完全一致,故直接复用 snellv6 的 SessionKey / NewAEAD / Nonce。版本→cipher 固定:
//
//	v1 = ChaCha20-Poly1305(32B key)   v2/v3 = AES-128-GCM(16B key)
//	v2 的 CONNECT 命令用 0x05(ConnectV2),v1/v3 用 0x01;UDP(cmd 6)v3+ 才有。
//
// 参照 mihomo transport/snell(version<4 走 shadowaead)与 go-snell-v1/v2/v3,逐字节对齐、不改线格式。
package snellv123

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/LOVECHEN/ntr/proto/snell/internal/snellv6"
)

const ssPayloadMask = 0x3FFF // shadowaead 单块最大载荷

// SenderSS 以 shadowsocks-AEAD 分帧编码一个方向(salt 首发一次,随后 [Seal(len)][Seal(payload)] 块)。
type SenderSS struct {
	psk     []byte
	chacha  bool
	aead    cipher.AEAD
	nonce   snellv6.Nonce
	started bool
	salt    [16]byte
}

// NewSenderSS 建编码器。chacha=true 选 v1(ChaCha20/32B),false 选 v2/v3(AES-128/16B)。
func NewSenderSS(psk []byte, chacha bool) *SenderSS { return &SenderSS{psk: psk, chacha: chacha} }

func (s *SenderSS) EncodeChunk(payload []byte) ([]byte, error) {
	var out []byte
	if !s.started {
		if _, err := rand.Read(s.salt[:]); err != nil {
			return nil, err
		}
		key, err := snellv6.SessionKey(s.psk, s.salt[:])
		if err != nil {
			return nil, err
		}
		if s.aead, err = snellv6.NewAEAD(key, s.chacha); err != nil {
			return nil, err
		}
		out = append(out, s.salt[:]...)
		s.started = true
	}
	if len(payload) == 0 { // 零长块 = EOF / 半关标记
		var lb [2]byte
		out = append(out, s.aead.Seal(nil, s.nonce[:], lb[:], nil)...)
		s.nonce.Inc()
		return out, nil
	}
	for off := 0; off < len(payload); {
		nr := min(len(payload)-off, ssPayloadMask)
		lb := [2]byte{byte(nr >> 8), byte(nr)}
		out = append(out, s.aead.Seal(nil, s.nonce[:], lb[:], nil)...)
		s.nonce.Inc()
		out = append(out, s.aead.Seal(nil, s.nonce[:], payload[off:off+nr], nil)...)
		s.nonce.Inc()
		off += nr
	}
	return out, nil
}

// ReceiverSS 解一个方向的 shadowsocks-AEAD 分帧。
type ReceiverSS struct {
	psk     []byte
	chacha  bool
	aead    cipher.AEAD
	nonce   snellv6.Nonce
	started bool
	salt    [16]byte
}

// NewReceiverSS 建解码器。
func NewReceiverSS(psk []byte, chacha bool) *ReceiverSS { return &ReceiverSS{psk: psk, chacha: chacha} }

// Salt / UsesChaCha 满足 snellv6.chunkDecoder 接口(复用其 UDP 适配)。
func (r *ReceiverSS) Salt() [16]byte   { return r.salt }
func (r *ReceiverSS) UsesChaCha() bool { return r.chacha }

// DecodeChunk 读一个块的明文;零长块返回 (nil,nil)(EOF 标记,由上层判半关)。
func (r *ReceiverSS) DecodeChunk(rd io.Reader) ([]byte, error) {
	if !r.started {
		if _, err := io.ReadFull(rd, r.salt[:]); err != nil {
			return nil, err
		}
		key, err := snellv6.SessionKey(r.psk, r.salt[:])
		if err != nil {
			return nil, err
		}
		if r.aead, err = snellv6.NewAEAD(key, r.chacha); err != nil {
			return nil, err
		}
		r.started = true
	}
	tag := r.aead.Overhead()
	lenBuf := make([]byte, 2+tag)
	if _, err := io.ReadFull(rd, lenBuf); err != nil {
		return nil, err
	}
	lenPt, err := r.aead.Open(lenBuf[:0], r.nonce[:], lenBuf, nil)
	r.nonce.Inc()
	if err != nil {
		return nil, err
	}
	size := (int(lenPt[0])<<8 + int(lenPt[1])) & ssPayloadMask
	if size == 0 {
		return nil, nil // 零长块 / EOF 标记
	}
	payBuf := make([]byte, size+tag)
	if _, err := io.ReadFull(rd, payBuf); err != nil {
		return nil, err
	}
	payload, err := r.aead.Open(payBuf[:0], r.nonce[:], payBuf, nil)
	r.nonce.Inc()
	if err != nil {
		return nil, err
	}
	return payload, nil
}
