package snellv6

// Outbound traffic shaping — the byte-for-byte send path of the official server.
// Reproduces the chunk-size schedule (sub_39610/sub_39700), the postpad +
// minimum-size write shaping (sub_39B20/sub_39B90), and the chunk splitter
// (sub_3B990). With this, a sender's emitted byte stream matches the official
// server's traffic profile (modulo the inherently random salt/padding content),
// not just being wire-decodable.

import "encoding/binary"

// chunk/write profile accessors (offsets verified bit-exact vs golden CTX).
func (p *Profile) ChunkInitial() uint16     { return p.u16(200) }
func (p *Profile) ChunkGrowth() uint16      { return p.u16(296) }
func (p *Profile) ChunkJitter() uint16      { return p.u16(320) }
func (p *Profile) ChunkPolicy() uint32      { return binary.LittleEndian.Uint32(p.ctx[280:]) }
func (p *Profile) ChunkBucketCount() uint8  { return p.ctx[302] }
func (p *Profile) ChunkBucket(i int) uint16 { return p.u16(152 + 2*i) }
func (p *Profile) IdleReset() uint16        { return p.u16(324) }

func (p *Profile) WritePolicy() uint32       { return binary.LittleEndian.Uint32(p.ctx[180:]) }
func (p *Profile) WriteSeqCount() uint8      { return p.ctx[329] }
func (p *Profile) WriteBucketCount() uint8   { return p.ctx[202] }
func (p *Profile) WriteBucket(i int) uint16  { return p.u16(104 + 2*i) }
func (p *Profile) WriteSeq(i int) uint16     { return p.u16(214 + 2*i) }
func (p *Profile) WriteJitter() uint16       { return p.u16(276) }
func (p *Profile) WritePayloadFactor() uint8 { return p.ctx[286] }
func (p *Profile) PostpadBase() uint16       { return p.u16(272) }
func (p *Profile) PostpadMax() uint16        { return p.u16(176) }
func (p *Profile) PostInterval() uint8       { return p.ctx[246] }
func (p *Profile) PostField300() uint16      { return p.u16(300) }
func (p *Profile) PostField326() uint8       { return p.ctx[326] }

// routeSeed returns the sub-seed a runtime PRF domain routes to (sub_38C30).
func (p *Profile) routeSeed(domain uint32) uint64 {
	switch {
	case domain == 0 || domain == 1 || domain == 14 || domain == 15 || domain == 33 || domain == 34:
		return p.seed64(168)
	case domain == 2:
		return p.seed64(288)
	case domain == 3 || (domain >= 16 && domain <= 20):
		return p.seed64(96)
	case (domain >= 21 && domain <= 26) || domain == 38 || domain == 39:
		return p.seed64(264)
	case (domain >= 28 && domain <= 32) || (domain >= 35 && domain <= 37):
		return p.seed64(312)
	default: // 4..13, 27
		return p.seed64(192)
	}
}

// rtPRF is the runtime PRF for a domain at (idx, konst): sub_38D00.
func (p *Profile) rtPRF(domain, idx, konst uint32) uint32 {
	return runtimePRF(p.routeSeed(domain), domain, idx, konst)
}

// clamp16 mirrors sub_39610's tail: v in [64, chunk_max].
func clamp16(v, chunkMax uint32) uint16 {
	if uint16(v) >= uint16(chunkMax) {
		if uint16(chunkMax) <= 63 {
			return 64
		}
		return uint16(chunkMax)
	}
	if uint16(v) <= 63 {
		return 64
	}
	return uint16(v)
}

// chunkSize reproduces sub_39610: pick this chunk's size from `cur` (the running
// size) per chunk_policy, clamped to [64, chunk_max].
func (p *Profile) chunkSize(cur uint16, idx uint32) uint16 {
	v := uint32(cur)
	if cur == 0 {
		v = uint32(p.ChunkInitial())
	}
	switch p.ChunkPolicy() {
	case 1: // bucket
		bi := p.rtPRF(38, idx, v) % uint32(p.ChunkBucketCount())
		v = uint32(p.ChunkBucket(int(bi)))
	case 2: // running + jitter
		j := uint32(p.ChunkJitter())
		prf := p.rtPRF(39, idx, v)
		// sub_39610 loc_396B8: r10 = (int32)(cur+jit) >= 64 ? cur+jit : 64
		// (signed floor at 64 BEFORE the common clamp). Dead for real PSKs but
		// matches the binary exactly.
		sum := int32(v) + (int32(prf%(2*j+1)) - int32(j))
		if sum < 64 {
			v = 64
		} else {
			v = uint32(sum)
		}
	}
	return clamp16(v, uint32(p.ChunkMax()))
}

// advanceChunk reproduces sub_39700: grow the running size by chunk_growth,
// capped at chunk_max (init to chunk_initial when zero).
func (p *Profile) advanceChunk(cur uint16) uint16 {
	if cur == 0 {
		return p.ChunkInitial()
	}
	g := uint32(cur) + uint32(p.ChunkGrowth())
	if g < uint32(p.ChunkMax()) {
		return uint16(g)
	}
	return p.ChunkMax()
}

// Test/diagnostic hooks (exported wrappers over the shaping internals).
func (p *Profile) ChunkSizeForTest(cur uint16, idx uint32) uint16 { return p.chunkSize(cur, idx) }
func (p *Profile) AdvanceChunkForTest(cur uint16) uint16          { return p.advanceChunk(cur) }
func (p *Profile) PostpadLenForTest(idx uint32, prepad, payload int, first bool) int {
	return p.postpadLen(idx, prepad, payload, first)
}

// --- postpad shaping (sub_39B20 base + sub_39B90 minimum-size write shaping) ---

// postpadGate reproduces sub_39AE0: whether a postpad is emitted at all.
func (p *Profile) postpadGate(idx uint32, payload int) bool {
	interval := p.PostInterval()
	f300 := p.PostField300()
	f326 := p.PostField326()
	if uint32(f326) <= idx && (payload == 0 || uint32(payload) > uint32(f300)) {
		if interval != 0 {
			return idx%uint32(interval) == 0
		}
		return false
	}
	return true
}

// postpadBase reproduces sub_39B20: the PRF-chosen base postpad length.
func (p *Profile) postpadBase(idx uint32, payload int) int {
	if !p.postpadGate(idx, payload) {
		return 0
	}
	prf := p.rtPRF(34, idx, uint32(payload))
	return int(mapRange(prf, p.PostpadBase(), p.PostpadMax()))
}

// minSize reproduces sub_39B90: the minimum chunk total the write-shaper targets.
func (p *Profile) minSize(idx, total uint32) uint16 {
	if total > 0x5B3 { // > 1459
		if total > 0xFFFE {
			return 0xFFFF
		}
		return uint16(total)
	}
	var r10 uint32
	jitter := func(base uint32) uint32 {
		prf36 := p.rtPRF(36, idx, 0)
		wj := uint32(p.WriteJitter())
		jit := prf36%(2*wj+1) - wj // wraps; matches 32-bit sub
		nv := base + jit
		if int32(nv) > 0 {
			return nv
		}
		return 1
	}
	if uint32(p.WriteSeqCount()) > idx {
		base := uint32(p.WriteSeq(int(idx)))
		if p.WritePolicy() == 2 {
			r10 = jitter(base)
		} else {
			r10 = base
		}
	} else {
		bi := p.rtPRF(35, idx, total) % uint32(p.WriteBucketCount())
		base := uint32(p.WriteBucket(int(bi)))
		if p.WritePolicy() == 2 {
			r10 = jitter(base)
		} else {
			r10 = base
		}
	}
	// L_39C06: cap = min(730, total*write_payload_factor/100)
	cap730 := total * uint32(p.WritePayloadFactor()) / 100
	r11 := uint32(730)
	if uint16(cap730) < 730 {
		r11 = cap730
	}
	odd := p.rtPRF(35, idx, r11) & 1
	if odd == 1 {
		half := (r11 & 0xFFFF) >> 1
		if uint16(r10) > uint16(half) {
			r10 = r10 - half
		}
	} else {
		if (uint16(r10)+uint16(r11)) != 0 && uint32(uint16(r10))+uint32(uint16(r11)) <= 0xFFFF {
			r10 = r10 + r11
		} else if uint32(uint16(r11))+uint32(uint16(r10)) <= 0xFFFF {
			r10 = r10 + r11
		} else {
			r10 = 0xFFFFFFFF
		}
	}
	// L_39CB7: accumulate write buckets until >= total
	for total > uint32(uint16(r10)) {
		bi2 := p.rtPRF(37, idx, r10) % uint32(p.WriteBucketCount())
		bucket := uint32(p.WriteBucket(int(bi2)))
		if uint32(uint16(r10)) >= bucket {
			delta := uint32(p.PostpadMax())
			r11 += delta
			r10 += delta
			if r11 > 0xFFFF {
				r10 = 0xFFFFFFFF
			}
		} else {
			r10 = bucket
		}
	}
	return uint16(r10)
}

// postpadLen computes the full postpad for a chunk (base + min-size extension),
// accounting for the first chunk's prefix region (sub_3B020 send path).
func (p *Profile) postpadLen(idx uint32, prepad, payload int, firstChunk bool) int {
	base := p.postpadBase(idx, payload)
	tagged := 0
	if payload != 0 {
		tagged = 16
	}
	total := prepad + base + payload + 23 + tagged
	if firstChunk {
		total += int(p.PrefixLen()) + 16
	}
	minsz := int(p.minSize(idx, uint32(total)))
	if total < minsz {
		base += min(minsz-total, 730) // extend postpad toward the min size
	}
	// b3-only: the FIRST chunk applies an additional postpad floor AFTER the
	// shared minSize extension (sub_3B150 @0x3276 -> sub_39D90).
	if firstChunk {
		base = p.firstChunkPostpadFloor(int(p.PrefixLen()), prepad, base, payload)
	}
	return base
}

// firstChunkPostpadFloor ports b3's sub_39D90 (size 134): for the first chunk
// only, bump the postpad so the chunk's framing overhead reaches a payload-
// proportional target. Applied to the already-minSize-extended postpad.
//
//	overhead = prefixLen + prepad + postpadBase
//	target   = max(192, (25*(payload + 55 - (payload==0?16:0)) + 74) / 75)
//	if overhead >= target -> keep postpadBase
//	else                  -> min(target - prefixLen - prepad, 730 + PostpadMax@176)
//
// sub_39BA0 is a 2-instruction helper that just returns the constant 730; its
// >0xFFFE error sentinel is unreachable here because 730+PostpadMax is clamped
// to <= 1460 (PostpadMax@176 <= 730).
func (p *Profile) firstChunkPostpadFloor(prefixLen, prepad, postpadBase, payload int) int {
	adj := 0
	if payload == 0 {
		adj = 16
	}
	target := (25*(payload+55-adj) + 74) / 75
	if target < 192 {
		target = 192
	}
	if prefixLen+prepad+postpadBase >= target {
		return postpadBase
	}
	cand := target - prefixLen - prepad
	if capv := 730 + int(p.PostpadMax()); cand > capv {
		cand = capv
	}
	return cand
}
