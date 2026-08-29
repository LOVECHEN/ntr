package snellv6

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// --- deterministic length schedule (consumed by both peers) -------------

// PrefixLen is the handshake prefix region size (sub_3AAE0): a per-connection
// constant. prefix_len = mapRange(prf32(RouteSeed33,33,0,0x7053), preMin, preMax).
func (p *Profile) PrefixLen() int {
	prf := prf32(p.RouteSeed33(), 33, 0, 0x7053)
	return int(mapRange(prf, p.PreSaltMin(), p.PreSaltMax()))
}

// Prepad is the pre-header padding length for chunk `idx` (sub_395E0):
// mapRange(runtimePRF(d=33, idxArg=idx, konstArg=0), padMin, padMax).
// The receiver MUST recompute this to locate the header — it is NOT on the wire.
func (p *Profile) Prepad(idx uint32) int {
	prf := runtimePRF(p.RouteSeed33(), 33, idx, 0)
	return int(mapRange(prf, p.PaddingMin(), p.PaddingMax()))
}

// --- one transport direction (mirrors one of the binary's two ctx) ------

// Sender encodes plaintext payloads into the v6 wire format for one direction.
// The first EncodeChunk emits the handshake prefix (random region with the
// scattered salt), derives the Argon2id session key, then frames the chunk.
type Sender struct {
	prof      *Profile
	psk       []byte
	aead      cipher.AEAD
	nonce     Nonce
	idx       uint32
	started   bool
	chacha    bool
	salt      [16]byte
	curSize   uint16       // running chunk size (ctx+80)
	lastWrite int64        // last write unix time (ctx+88), 0 = none yet
	nowFn     func() int64 // injectable clock for the idle reset (tests)
	// Reused per-chunk scratch (a Sender is driven by one goroutine per
	// connection → race-free). Cuts prepad/postpad/payload-seal allocations to
	// amortized zero, reducing GC pressure under many concurrent connections. The
	// produced wire bytes are unchanged (verified bit-exact by the golden tests).
	bufPrepad, bufPostpad, bufPay []byte

	// Shaped enables full official-server traffic shaping: the chunk-size
	// schedule (sub_3B990/sub_39610), PRF postpad + minimum-size write shaping
	// (sub_39B20/sub_39B90), and the payload byte-mix. On by default. When off,
	// each EncodeChunk emits one minimal chunk (postpad=0) — still wire-valid.
	Shaped bool

	// Mode selects the b3 encryption mode (config key `mode`). ModeDefault uses
	// the full obfuscation below; ModeUnshaped/ModeUnsafeRaw take the dedicated
	// paths in mode.go. Server and client mode MUST match (no negotiation).
	Mode Mode
}

// NewSender builds an encoder. If chacha is true the AEAD is ChaCha20-Poly1305,
// else AES-128-GCM (the two wire ciphers; both 12B nonce + 16B tag).
func NewSender(psk []byte, chacha bool) *Sender {
	return NewSenderWithProfile(psk, chacha, DeriveProfile(psk))
}

// NewSenderWithProfile is NewSender with a precomputed profile, so a caller that
// opens many connections under one PSK derives the (deterministic, read-only)
// profile once and shares it. The Profile is immutable after DeriveProfile, so
// one instance is safe to share across concurrent senders. Wire output is
// identical to NewSender. (DeriveProfile is the dominant per-connection setup
// cost — splitmix64 PRF over 42 fields + two bucket arrays.)
func NewSenderWithProfile(psk []byte, chacha bool, prof *Profile) *Sender {
	return &Sender{prof: prof, psk: psk, chacha: chacha, Shaped: true}
}

// Salt returns the generated/observed connection salt (valid after first chunk).
func (s *Sender) Salt() [16]byte { return s.salt }

func (s *Sender) now() int64 {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now().Unix()
}

// EncodeChunk frames one application write. With shaping on it reproduces the
// official server's outbound traffic profile: an idle-reset check, then the
// payload split into chunks per the chunk-size schedule, each chunk fully
// padded/mixed (sub_3B990).
func (s *Sender) EncodeChunk(payload []byte) ([]byte, error) {
	switch s.Mode {
	case ModeUnshaped:
		return s.encodeUnshaped(payload)
	case ModeUnsafeRaw:
		return s.encodeRaw(payload)
	}
	if !s.Shaped {
		return s.encodeOne(payload)
	}
	// sub_3B990 head: idle reset of the running chunk size.
	now := s.now()
	if s.lastWrite == 0 || now-s.lastWrite > int64(s.prof.IdleReset()) {
		s.curSize = s.prof.ChunkInitial()
	}
	s.lastWrite = now

	sz := s.prof.chunkSize(s.curSize, s.idx)
	// b3-only: the VERY first chunk (global idx==0) has its size capped at the
	// first_chunk_cap (sub_3BD00 @0x3718: `if (!idx && v9 > ctx[186]) v9 = ctx[186]`).
	// Capping sz here forces an earlier split when the first write is larger than
	// the cap; later chunks (idx>=1) are not capped.
	if s.idx == 0 && sz > s.prof.FirstChunkCap() {
		sz = s.prof.FirstChunkCap()
	}
	s.curSize = s.prof.advanceChunk(s.curSize)
	if len(payload) == 0 || len(payload) <= int(sz) {
		return s.encodeOne(payload)
	}
	// split into chunks of `sz`, resizing per chunk
	var out []byte
	for off := 0; off < len(payload); {
		n := min(len(payload)-off, int(sz))
		c, err := s.encodeOne(payload[off : off+n])
		if err != nil {
			return nil, err
		}
		out = append(out, c...)
		off += n
		if off >= len(payload) {
			break
		}
		sz = s.prof.chunkSize(s.curSize, s.idx)
		s.curSize = s.prof.advanceChunk(s.curSize)
	}
	return out, nil
}

// ensureBuf returns buf resliced to length n, reusing its backing array when the
// capacity allows, else a fresh slice. Used for per-instance scratch reused
// across chunks (the callers fully overwrite the returned slice).
func ensureBuf(buf []byte, n int) []byte {
	if cap(buf) >= n {
		return buf[:n]
	}
	return make([]byte, n)
}

// encodeOne frames a single chunk (sub_3B020): prefix (first chunk only),
// prepad, AEAD header, postpad, AEAD payload, payload mix. The output is built
// into one pre-sized buffer and the pad/seal scratch is reused per Sender, so a
// steady-state chunk allocates only the returned slice (wire bytes unchanged;
// the returned slice is freshly allocated, so callers may keep it as before).
func (s *Sender) encodeOne(payload []byte) ([]byte, error) {
	if len(payload) > 0xFFFF {
		return nil, fmt.Errorf("snellv6: chunk payload %d exceeds 65535", len(payload))
	}
	firstChunk := !s.started
	prepadLen := s.prof.Prepad(s.idx)
	postpadLen := 0
	if s.Shaped {
		postpadLen = s.prof.postpadLen(s.idx, prepadLen, len(payload), firstChunk)
	}
	regionLen := 0
	if firstChunk {
		regionLen = s.prof.PrefixLen() + 16
	}
	// Pre-size the single output allocation (AAD always uses the separate scratch
	// below, so even if this estimate is off and out reallocs, no aliasing).
	total := regionLen + prepadLen + 23 + postpadLen // 23 = 7B header + 16B AEAD tag
	if len(payload) > 0 {
		total += len(payload) + 16
	}
	out := make([]byte, 0, total)

	if firstChunk {
		region := make([]byte, regionLen)
		s.prof.prfPad(0xFFFFFFFF, region) // PSK-deterministic padding (sub_39750)
		if _, err := rand.Read(s.salt[:]); err != nil {
			return nil, err
		}
		s.prof.ScatterSalt(region, s.salt) // overwrite 16 positions with the random salt
		key, err := SessionKey(s.psk, s.salt[:])
		if err != nil {
			return nil, err
		}
		if s.aead, err = NewAEAD(key, s.chacha); err != nil {
			return nil, err
		}
		s.nonce = Nonce{}
		out = append(out, region...)
		s.started = true
	}

	// prepad (PSK-deterministic prfPad; its on-wire bytes are the header AAD).
	// Reused scratch, fully overwritten by prfPad; separate backing from out.
	s.bufPrepad = ensureBuf(s.bufPrepad, prepadLen)
	prepad := s.bufPrepad
	s.prof.prfPad(s.idx, prepad)
	out = append(out, prepad...)

	var hdr [7]byte
	hdr[0] = 4
	binary.BigEndian.PutUint16(hdr[3:5], uint16(postpadLen))
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))
	out = s.aead.Seal(out, s.nonce[:], hdr[:], prepad) // append encHdr into out (AAD = prepad scratch)
	s.nonce.Inc()

	// postpad (reused scratch, fully overwritten by prfPad).
	s.bufPostpad = ensureBuf(s.bufPostpad, postpadLen)
	postpad := s.bufPostpad
	s.prof.prfPad(s.idx, postpad)
	if len(payload) > 0 {
		// AAD = un-mixed postpad; then mix swaps postpad <-> ciphertext (self-inverse).
		s.bufPay = s.aead.Seal(s.bufPay[:0], s.nonce[:], payload, postpad)
		s.nonce.Inc()
		s.prof.MixPayload(s.idx, postpad, s.bufPay)
		out = append(out, postpad...)
		out = append(out, s.bufPay...)
	} else {
		out = append(out, postpad...)
	}
	s.idx++
	return out, nil
}

// Receiver decodes one direction of the v6 wire format from a stream.
type Receiver struct {
	prof    *Profile
	psk     []byte
	aead    cipher.AEAD
	nonce   Nonce
	idx     uint32
	started bool
	chacha  bool // set once auto-detected
	salt    [16]byte

	// Mode selects the b3 encryption mode; must match the sender's.
	Mode Mode

	// last-chunk structure, recorded for analysis/diagnostics.
	lastPrepad, lastPostpad, lastPayload int

	// Reused per-chunk read/scratch (one goroutine per connection → race-free).
	// The RETURNED payload stays freshly allocated (Open(nil)), so callers keep the
	// same ownership contract; only the throwaway prepad/encHdr/postpad/ciphertext
	// reads are pooled. Wire bytes unchanged.
	bufPrepad, bufEncHdr, bufHdr, bufPostpad, bufEncPay []byte
}

// LastChunkShape returns (prepad, postpad, payload) byte lengths of the most
// recently decoded chunk. Useful for verifying a sender's traffic shaping.
func (r *Receiver) LastChunkShape() (prepad, postpad, payload int) {
	return r.lastPrepad, r.lastPostpad, r.lastPayload
}

func NewReceiver(psk []byte) *Receiver {
	return NewReceiverWithProfile(psk, DeriveProfile(psk))
}

// NewReceiverWithProfile is NewReceiver with a precomputed profile (see
// NewSenderWithProfile): derive once per PSK, share the read-only profile across
// connections. Wire behavior is identical.
func NewReceiverWithProfile(psk []byte, prof *Profile) *Receiver {
	return &Receiver{prof: prof, psk: psk}
}

func (r *Receiver) Salt() [16]byte { return r.salt }

// UsesChaCha reports the cipher detected on the first header.
func (r *Receiver) UsesChaCha() bool { return r.chacha }

var errBadHeader = errors.New("snellv6: header AEAD/type check failed")

// DecodeChunk reads exactly one chunk (consuming the handshake prefix first).
// Returns the recovered payload (possibly empty for a zero-length chunk).
func (r *Receiver) DecodeChunk(rd io.Reader) ([]byte, error) {
	switch r.Mode {
	case ModeUnshaped:
		return r.decodeUnshaped(rd)
	case ModeUnsafeRaw:
		return r.decodeRaw(rd)
	}
	if !r.started {
		region := make([]byte, r.prof.PrefixLen()+16)
		if _, err := io.ReadFull(rd, region); err != nil {
			return nil, err
		}
		r.salt = r.prof.DescatterSalt(region)
		key, err := SessionKey(r.psk, r.salt[:])
		if err != nil {
			return nil, err
		}
		// AAD/nonce are deterministic, so the GCM tag tells us the cipher.
		prepad := make([]byte, r.prof.Prepad(r.idx))
		if _, err := io.ReadFull(rd, prepad); err != nil {
			return nil, err
		}
		encHdr := make([]byte, 23)
		if _, err := io.ReadFull(rd, encHdr); err != nil {
			return nil, err
		}
		hdr, chacha, err := r.openFirstHeader(key, prepad, encHdr)
		if err != nil {
			return nil, err
		}
		r.chacha = chacha
		r.started = true
		r.nonce.Inc()
		return r.finishChunk(rd, hdr)
	}

	r.bufPrepad = ensureBuf(r.bufPrepad, r.prof.Prepad(r.idx))
	prepad := r.bufPrepad
	if _, err := io.ReadFull(rd, prepad); err != nil {
		return nil, err
	}
	r.bufEncHdr = ensureBuf(r.bufEncHdr, 23)
	encHdr := r.bufEncHdr
	if _, err := io.ReadFull(rd, encHdr); err != nil {
		return nil, err
	}
	hdr, err := r.aead.Open(r.bufHdr[:0], r.nonce[:], encHdr, prepad)
	if err != nil {
		return nil, err
	}
	r.bufHdr = hdr // keep the (grown) backing for reuse
	// len guard mirrors openFirstHeader's `len(pt)==7`: a legal hdr is always 7B
	// (23B encHdr − 16B GCM tag), so this never rejects a valid frame — it只消除
	// finishChunk 的 hdr[3:5]/hdr[5:7] 隐式长度假设(防御纵深,wire 不变)。
	if len(hdr) != 7 || hdr[0] != 4 {
		return nil, errBadHeader
	}
	r.nonce.Inc()
	return r.finishChunk(rd, hdr)
}

// openFirstHeader tries AES-128-GCM then ChaCha20-Poly1305 against the first
// header, locking in r.aead with the winning cipher.
func (r *Receiver) openFirstHeader(key, prepad, encHdr []byte) (hdr []byte, chacha bool, err error) {
	for _, useChaCha := range []bool{false, true} {
		aead, e := NewAEAD(key, useChaCha)
		if e != nil {
			continue
		}
		pt, e := aead.Open(nil, r.nonce[:], encHdr, prepad)
		if e == nil && len(pt) == 7 && pt[0] == 4 {
			r.aead = aead
			return pt, useChaCha, nil
		}
	}
	return nil, false, errBadHeader
}

func (r *Receiver) finishChunk(rd io.Reader, hdr []byte) ([]byte, error) {
	postpadLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(hdr[5:7]))
	r.lastPrepad = r.prof.Prepad(r.idx) // prepad used for this chunk (pre-increment)
	r.lastPostpad = postpadLen
	r.lastPayload = payloadLen
	r.idx++
	// The encoder writes the postpad region after the header even for a
	// zero-length payload (sub_3B020), and the real decoder skips it
	// (sub_3B3F0: consumes prepad+23+postpad when payload_len==0). Consume it
	// unconditionally, else the stream desyncs on the next chunk.
	r.bufPostpad = ensureBuf(r.bufPostpad, postpadLen)
	postpad := r.bufPostpad
	if _, err := io.ReadFull(rd, postpad); err != nil {
		return nil, err
	}
	if payloadLen == 0 {
		return []byte{}, nil
	}
	r.bufEncPay = ensureBuf(r.bufEncPay, payloadLen+16)
	encPayload := r.bufEncPay
	if _, err := io.ReadFull(rd, encPayload); err != nil {
		return nil, err
	}
	// un-mix: swap postpad <-> payload-ciphertext (self-inverse)
	r.prof.MixPayload(r.idx-1, postpad, encPayload)
	payload, err := r.aead.Open(nil, r.nonce[:], encPayload, postpad) // fresh: returned to caller
	if err != nil {
		return nil, err
	}
	r.nonce.Inc()
	return payload, nil
}
