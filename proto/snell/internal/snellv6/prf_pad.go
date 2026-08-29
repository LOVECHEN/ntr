package snellv6

import (
	"encoding/binary"
	"math/bits"
)

// --- v6 padding generator (sub_39750) ---------------------------------------
//
// The v6 encoder (sub_3B020) fills its three padding regions (handshake prefix,
// per-chunk prepad, per-chunk postpad) with PSK-deterministic content via
// sub_39750, NOT random bytes. The receiver discards padding CONTENT (only the
// mix positions, set by len1/datalen, affect decoding), so random padding still
// interoperates — but to match the official server byte-for-byte (and its
// anti-DPI entropy bands) we reproduce the generator exactly.
//
// Pointer note: sub_3B020 calls sub_39750((int*)ctx + 24, ...) = ctx+96, and the
// mix sub_38E80 (already ported) receives the same ctx+96. profile.go maps its
// fields as ctx[X] == that-a1 + (X-96); hence sub_39750's a1+N == Profile.ctx[N+96].
//
// Algorithm: (1) fill the region with a splitmix64 keystream (sub_38D20), then
// (2) apply one of 4 transforms selected by ctx[252] (a1+156).

// padTable is byte_1F5F80[0..127] (sub_38DF0 lookup; 8 rows of 16, v4=0..7).
var padTable = [128]byte{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // v4=0 (unused; v4>=1)
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, // v4=1
	0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24, // v4=2
	0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0, // v4=3
	0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78, 0xf0, // v4=4
	0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f, // v4=5
	0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb, // v4=6
	0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, // v4=7
}

// padRouteSeed routes a keystream domain to its ctx seed (sub_38C30 switch with
// a1=ctx+96): domain 0/1 (cases 0,1,...) -> [a1+0x48]=ctx[168]; domain 2 ->
// [a1+0xC0]=ctx[288]. (domain 3 -> ctx[96], the default -> ctx[192].)
func (p *Profile) padRouteSeed(domain uint32) uint64 {
	switch domain {
	case 2:
		return p.seed64(288)
	case 3:
		return p.seed64(96)
	default: // 0, 1
		return p.seed64(168)
	}
}

// padKeystream fills out with the splitmix64 keystream (sub_38D20): the route
// seed is mixed with domain/konst/len, then state += GAMMA, out = fmix64(state)
// per 8-byte block.
func (p *Profile) padKeystream(domain, konst uint32, out []byte) {
	state := p.padRouteSeed(domain) ^
		(0xB57DE1F3F82CB33F + uint64(konst)*0xD6E8FEB86659FD93) ^
		(uint64(domain) * 0xA24BAED4963EE407) ^
		(uint64(len(out))*0x165667B19E3779F9 + 0xD4CD3E7B14A36D7)
	var blk [8]byte
	for off := 0; off < len(out); off += 8 {
		state += 0x9E3779B97F4A7C15
		binary.LittleEndian.PutUint64(blk[:], fmix64(state))
		copy(out[off:], blk[:])
	}
}

// ProfilePad returns the v6 PSK-deterministic padding region of length n for
// chunk idx (use 0xFFFFFFFF for the handshake prefix) — exported for
// golden-vector validation against the real binary.
func ProfilePad(psk []byte, idx uint32, n int) []byte {
	out := make([]byte, n)
	DeriveProfile(psk).prfPad(idx, out)
	return out
}

// prfPad fills out with the PSK-deterministic padding (sub_39750). idx is the
// chunk index (0xFFFFFFFF for the handshake prefix region).
func (p *Profile) prfPad(idx uint32, out []byte) {
	if len(out) == 0 {
		return
	}
	p.padKeystream(0, idx, out) // splitmix64 keystream foundation
	switch p.ctx[252] {         // mode = a1+156
	case 0:
		p.padMode0(idx, out)
	case 1:
		p.padMode1(out)
	case 2:
		p.padMode2(out)
	case 3:
		p.padMode3(idx, out)
	}
}

// padMode0: table-substitution byte transform (sub_38DF0 per byte).
func (p *Profile) padMode0(idx uint32, out []byte) {
	prf := runtimePRF(p.seed64(168), 1, idx, 0)                         // sub_38D00(ctx,1,idx,0)
	mr := uint32(mapRange(prf, uint16(p.ctx[184]), uint16(p.ctx[298]))) // sub_38B30(prf,ctx[184],ctx[298])
	e := mr << 3
	var r9 byte = 1
	switch {
	case e <= 49:
		r9 = 1
	case e > 749:
		r9 = 7
	default:
		r9 = byte((e + 50) / 100)
	}
	for i := range out {
		mixer := byte(uint32(i) + uint32(out[i])) // (i + buf[i]) & 0xFF
		out[i] = pad38DF0(out[i], r9, mixer)
	}
}

// pad38DF0 reproduces sub_38DF0: ROL of a table byte.
func pad38DF0(a1, a2, a3 byte) byte {
	v4 := byte(1)
	if a2 != 0 {
		v4 = 7
		if a2 <= 7 {
			v4 = a2
		}
	}
	v5 := a3 ^ (a1 >> 4)
	v6 := padTable[16*int(v4)+int((a1^a3)&0xF)]
	if v5&7 == 0 {
		return v6
	}
	return bits.RotateLeft8(v6, int(v5&7))
}

// padMode1: per-byte entropy-band selection ([32,126]/[128,191]/[192,255]).
func (p *Profile) padMode1(out []byte) {
	c182 := uint32(p.ctx[278]) // a1+182
	c231 := uint32(p.ctx[327]) // a1+231
	c116 := uint32(p.ctx[212]) // a1+116
	band := c116 + c182 + c231
	for i := range out {
		b := uint32(out[i])
		rem := b % band
		switch {
		case c182 > rem:
			out[i] = pad38E30(byte(uint32(i)+b), 32, 126)
		case rem >= c182+c231:
			out[i] = pad38E30(byte(7*uint32(i)+b), 192, 255)
		default:
			out[i] = pad38E30(byte(uint32(i)^b), 128, 191)
		}
	}
}

// pad38E30 reproduces sub_38E30: lo + seed % (hi-lo+1).
func pad38E30(seed, lo, hi byte) byte { return lo + seed%(hi-lo+1) }

// padMode2: nibble manipulation.
func (p *Profile) padMode2(out []byte) {
	c214 := uint32(p.ctx[310]) // a1+214
	for i := range out {
		b := uint32(out[i])
		hi := ((b >> 4) + (uint32(i) & 3) + 3) << 4
		lo := (c214 + (b & 0xF) + (uint32(i) & 1)) % 10
		out[i] = byte(hi | lo)
	}
}

// padMode3: second keystream (domain 2) XOR + digit substitution.
func (p *Profile) padMode3(idx uint32, out []byte) {
	var ks [32]byte
	p.padKeystream(2, idx, ks[:]) // sub_38D20(ctx,2,idx,stack,32)
	c164 := uint32(p.ctx[260])    // a1+164
	v8 := uint32(4)
	if e := 4 * c164; e > 3 {
		if e <= 32 {
			v8 = e
		} else {
			v8 = 32
		}
	}
	v10 := uint32(p.ctx[328]) // a1+232
	if v10 < 5 {
		v10 = 5
	}
	for i := range out {
		switch m := uint32(i) % v10; {
		case m < v10-3:
			out[i] = ks[uint32(i)%v8] ^ byte(uint32(i)*(c164+3))
		case m < v10-1:
			out[i] = out[i]%10 + 48
		} // else: unchanged (keystream byte)
	}
}

// ProfileMode returns the v6 padding mode selector (ctx[252]) for a PSK.
func ProfileMode(psk []byte) byte { return DeriveProfile(psk).ctx[252] }
