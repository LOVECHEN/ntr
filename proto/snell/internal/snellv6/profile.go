package snellv6

import "encoding/binary"

// Profile is the PSK-derived deployment profile (the 0x158-byte cipher context
// the official binary builds in sub_39D90). Field names follow the official
// blog's sn_shape_profile_t where the mapping is clear; the canonical key is
// the byte offset into the context, which is what we validate against.
//
// The ENTIRE derivation below is CONFIRMED bit-exact against a golden CTX dump
// from the running v6.0.0b2 binary (see testdata/golden.txt): master seed, all
// 7 sub-seeds, all 42 fields, and both bucket arrays reproduce exactly. [OK]
type Profile struct {
	ctx [0x158]byte // raw context mirror; authoritative
}

// the 7 (domain, magic) sub-seed pairs, stored at these ctx offsets. [OK]
var subseedSpec = []struct {
	off    int
	domain uint32
	magic  uint64
}{
	{192, 5, 0xB46C2E7D9A1538F1},
	{168, 0, 0x5D9217C083E64AB9},
	{288, 2, 0xA71F0C54D8396E2B},
	{232, 3, 0x3E8A91B52740F6CD},
	{96, 16, 0xC9F4260B7D1E835A},
	{264, 21, 0x62D0B5E19C4A783F},
	{312, 28, 0x917B3C48E6A205D4},
}

// routeDomain maps a query domain to the sub-seed used by sub_39D70/sub_38C30. [OK]
func routeDomain(ss map[uint32]uint64, dom uint32) uint64 {
	switch {
	case dom == 0 || dom == 1 || dom == 14 || dom == 15 || dom == 33 || dom == 34:
		return ss[0]
	case dom == 2:
		return ss[2]
	case dom == 3 || (dom >= 16 && dom <= 20):
		return ss[16]
	case (dom >= 21 && dom <= 26) || dom == 38 || dom == 39:
		return ss[21]
	case (dom >= 28 && dom <= 32) || (dom >= 35 && dom <= 37):
		return ss[28]
	default: // 4..13, 27
		return ss[5]
	}
}

// DeriveProfile builds the profile deterministically from the PSK. [OK]
func DeriveProfile(psk []byte) *Profile {
	p := &Profile{}
	ms := MasterSeed(psk)
	// store master seed at +120 (as the binary does)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(p.ctx[120+8*i:], ms[i])
	}
	// sub-seeds
	ss := map[uint32]uint64{}
	for _, s := range subseedSpec {
		v := subSeed(ms, s.domain, s.magic)
		ss[s.domain] = v
		binary.LittleEndian.PutUint64(p.ctx[s.off:], v)
	}
	// field PRF: prf32(routed_seed(domain), kind=domain, konst=0, index=third)
	F := func(dom, third uint32) uint32 { return prf32(routeDomain(ss, dom), dom, 0, third) }

	put16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(p.ctx[off:], v) }
	put8 := func(off int, v uint8) { p.ctx[off] = v }
	put32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(p.ctx[off:], v) }

	// --- scalar fields (offset, derivation) -- order matters for the pairs ---
	put32(240, F(5, 0))
	put32(252, F(6, 0)&3)
	f272 := mapRange(F(7, 0), 24, 160)
	put16(272, f272)
	put16(176, f272+mapRange(F(8, 0), 160, 960)) // base+delta pair with 272
	put8(326, uint8(mapRange(F(9, 0), 2, 8)))
	put8(246, uint8(mapRange(F(10, 0), 2, 11)))
	put16(300, mapRange(F(11, 0), 96, 768))
	put8(184, uint8(mapRange(F(12, 0), 24, 41)))
	put8(298, uint8(mapRange(F(13, 0), 58, 76)))
	put8(278, uint8(mapRange(F(6, 1), 24, 128)))
	put8(327, uint8(mapRange(F(6, 2), 16, 96)))
	put8(212, uint8(mapRange(F(6, 3), 16, 96)))
	put8(310, uint8(mapRange(F(6, 4), 0, 9)))
	put8(260, uint8(mapRange(F(6, 5), 1, 8)))
	put8(328, uint8(mapRange(F(6, 6), 7, 23))) // padding-gen param (read by prfPad @ctx+328; NOT salt_mask_stride, which is ctx+322)
	psMin := mapRange(F(14, 28755), 16, 96)
	put16(204, psMin)                                 // pre_salt_min
	put16(304, psMin+mapRange(F(15, 28755), 16, 160)) // pre_salt_max = min+delta
	put8(274, uint8(mapRange(F(17, 20903), 1, 4)))
	put8(322, uint8(mapRange(F(18, 20903), 17, 251)))
	padMin := mapRange(F(14, 0), 8, 80)
	put16(284, padMin)                             // padding_min
	put16(188, padMin+mapRange(F(15, 0), 16, 160)) // padding_max = min+delta (b3 moved 186->188)
	put32(208, F(16, 0)%3)                         // padding_generator
	put8(306, uint8(mapRange(F(17, 0), 1, 3)))
	put16(244, mapRange(F(18, 0), 2, 13)) // padding_interval
	put16(308, mapRange(F(19, 0), 0, 15))
	put16(258, mapRange(F(20, 0), 8, 64))
	put32(280, F(21, 0)%3)                    // chunk_policy
	put16(200, mapRange(F(22, 0), 512, 1460)) // chunk_initial_size
	// b3-only first-chunk SIZE cap (sub_39E40 @0x3a3f8, store to ctx+186). Same
	// PRF domain (22) as chunk_initial but a DISTINCT konst (61820 = 0xF17C), so
	// it is an independent draw, not a remap of chunk_initial. b3 relocated
	// padding_max from 186 to 188 to make room for it (see above).
	put16(186, mapRange(F(22, 61820), 256, 768)) // first_chunk_size_cap
	cmax := mapRange(F(23, 0), 0x2000, 0x3FFF)
	put16(248, cmax)                           // chunk_max_size
	put16(296, mapRange(F(24, 0), 1024, 4096)) // chunk_growth_step
	put16(320, mapRange(F(25, 0), 16, 192))    // chunk_jitter
	put8(302, 8)                               // chunk_bucket_count
	for i := uint32(0); i < 8; i++ {
		put16(152+2*int(i), mapRange(F(26, i), 4096, cmax)) // chunk_buckets
	}
	put16(324, mapRange(F(27, 0), 12, 90)) // idle_reset_seconds
	put32(180, F(28, 0)%3)                 // write_policy
	fw := uint8(mapRange(F(29, 0), 4, 8))
	put8(256, fw) // first_write_count
	put8(202, 8)  // write_bucket_count
	for i := uint32(0); i < 8; i++ {
		put16(104+2*int(i), mapRange(F(30, i), 320, 1460)) // write_buckets
	}
	put8(329, fw) // write_sequence_count = first_write_count
	for i := uint32(0); i < uint32(fw); i++ {
		put16(214+2*int(i), mapRange(F(31, i), 360, 1460)) // write_sequence
	}
	put16(276, mapRange(F(32, 0), 8, 96))           // write_jitter
	put8(286, uint8(mapRange(F(28, 20556), 8, 48))) // write_payload_factor

	p.clamp()
	return p
}

// clamp ports the sub_39D90 tail: bounds + min<=max normalization. For the
// golden PSK it is a no-op (raw values already in range), but boundary PSKs
// depend on it — especially the framing fields (pre_salt / padding / postpad
// ranges) which the handshake length schedule reads. [OK]
func (p *Profile) clamp() {
	g := func(o int) uint16 { return p.u16(o) }
	s := func(o int, v uint16) { binary.LittleEndian.PutUint16(p.ctx[o:], v) }
	capmin := func(lo, hi int, cap uint16) { // hi = min(hi,cap); lo = min(lo, hi)
		h := g(hi)
		if h > cap {
			h = cap
		}
		s(hi, h)
		if g(lo) > h {
			s(lo, h)
		}
	}
	// framing-relevant pairs (verified bit-exact against sub_39D90 tail):
	capmin(204, 304, 128) // pre_salt_min @204 <= pre_salt_max @304 <= 128
	capmin(284, 188, 128) // padding_min @284 <= padding_max @188 <= 128 (b3 layout)
	capmin(272, 176, 730) // postpad base @272 <= postpad max @176 <= 730

	// chunk sizing (sender-cosmetic; receiver reads payload_len from header).
	cmin := g(200)
	if cmin > 1460 {
		cmin = 1460
	}
	if cmin < 96 {
		cmin = 96
	}
	s(200, cmin)
	// b3 first-chunk cap clamp (sub_39E40 @2692-2698): cap the raw cap at
	// v67 = min(chunk_initial_clamped, 768), THEN floor at 256. The floor wins
	// when chunk_initial < 256, so the cap can exceed chunk_initial in that case
	// (matches the binary's `if v68>v67{v68=v67}; if v68<256{v68=256}` order).
	v67 := cmin
	if v67 > 768 {
		v67 = 768
	}
	fc := g(186)
	if fc > v67 {
		fc = v67
	}
	if fc < 256 {
		fc = 256
	}
	s(186, fc)
	if g(248) < cmin {
		s(248, cmin) // chunk_max >= chunk_initial
	}
	if g(296) > 2920 {
		s(296, 2920) // chunk_growth_step
	}
	if g(320) > 182 {
		s(320, 182) // chunk_jitter
	}
	cmax := g(248)
	// chunk_buckets @152.. : clamp into [4096, chunk_max]
	for i := 0; i < int(p.ctx[302]); i++ {
		off := 152 + 2*i
		v := g(off)
		if v > cmax {
			v = cmax
		}
		if v < 4096 {
			v = 4096
		}
		s(off, v)
	}
	// write_buckets @104.. and write_sequence @214.. : clamp into [256, 1460]
	clampBuckets := func(base int, n int) {
		for i := 0; i < n; i++ {
			off := base + 2*i
			v := g(off)
			if v > 1460 {
				v = 1460
			}
			if v < 256 {
				v = 256
			}
			s(off, v)
		}
	}
	clampBuckets(104, int(p.ctx[202]))
	clampBuckets(214, int(p.ctx[329]))
}

// Raw returns the 0x158-byte context mirror (for golden-vector diffing).
func (p *Profile) Raw() []byte { return p.ctx[:] }

// Accessors for the fields a sender/receiver actually needs at runtime.
func (p *Profile) u16(o int) uint16    { return binary.LittleEndian.Uint16(p.ctx[o:]) }
func (p *Profile) seed64(o int) uint64 { return binary.LittleEndian.Uint64(p.ctx[o:]) }
func (p *Profile) PreSaltMin() uint16  { return p.u16(204) }
func (p *Profile) PreSaltMax() uint16  { return p.u16(304) }
func (p *Profile) PaddingMin() uint16  { return p.u16(284) }
func (p *Profile) PaddingMax() uint16  { return p.u16(188) }
func (p *Profile) ChunkMax() uint16    { return p.u16(248) }

// FirstChunkCap is the b3 first-chunk SIZE cap (ctx+186): the very first chunk's
// size is clamped down to this value (sub_3B970 @0x3718, gated on idx==0).
func (p *Profile) FirstChunkCap() uint16 { return p.u16(186) }

// --- on-the-wire framing parameters (offsets verified by disasm) ---
// RouteSeed33 is the sub-seed domains {0,1,14,15,33,34} route to (ctx+168);
// it drives prefix_len and prepad/postpad lengths. [OK sub_38C30 case 33/34]
func (p *Profile) RouteSeed33() uint64 { return p.seed64(168) }

// SaltSeed is the domain-3 sub-seed (ctx+232) used by BOTH the salt-scatter
// Fisher-Yates permutation and the salt keystream. [OK sub_3AB70/sub_38E50]
func (p *Profile) SaltSeed() uint64 { return p.seed64(232) }

// SaltPermRounds = ctx+274 (>=1); Fisher-Yates round count. [OK]
func (p *Profile) SaltPermRounds() uint8 { return p.ctx[274] }

// SaltMaskStride = ctx+322; per-index multiplier in the salt keystream. The
// keystream is (uint8)(i*stride ^ prf32(SaltSeed,2,20903,i)). [OK sub_38E50]
func (p *Profile) SaltMaskStride() uint8 { return p.ctx[322] }

// --- payload byte-mix (sub_38E80) parameters, addressed off ctx+96 ---
func (p *Profile) MixRounds() uint8    { return p.ctx[306] }                              // a1+210
func (p *Profile) MixMode() uint32     { return binary.LittleEndian.Uint32(p.ctx[208:]) } // a1+112
func (p *Profile) MixBlock() uint16    { return p.u16(258) }                              // a1+162
func (p *Profile) MixInterval() uint16 { return p.u16(244) }                              // a1+148
func (p *Profile) MixOffset() uint16   { return p.u16(308) }                              // a1+212
