package snellv6

// MixPayload is the byte-mixer sub_38E80: a self-inverse byte swap between two
// regions (on the wire: region1 = postpad, region2 = payload-ciphertext+tag).
// The encoder applies it after payload encryption; the decoder applies it again
// (same swaps) before payload decryption — being pure swaps, it is its own
// inverse. Operates on the first min(len(r1),len(r2)) bytes.
//
// MixMode (ctx+208) selects the schedule:
//
//	mode 0/2: stride swap — swap r1[pos]<->r2[pos] for pos=off, off+step, ...
//	          step = round%3 + MixInterval; off = MixOffset%step
//	          (mode 2 adds a runtime-PRF term to the offset — see note)
//	mode 1:   block swap — swap MixBlock-byte blocks at block indices
//	          {round&1, round&1+2, ...}
//
// Repeated MixRounds (ctx+306) times.
//
// VALIDATED for MixMode==0 (the golden PSK: rounds=3, interval=11, offset=11).
// Modes 1 and 2 are ported from the disasm but not yet golden-validated.
func (p *Profile) MixPayload(chunkIdx uint32, r1, r2 []byte) {
	if len(r1) == 0 || len(r2) == 0 {
		return
	}
	minlen := min(len(r1), len(r2))
	rounds := int(p.MixRounds())
	if rounds == 0 {
		return
	}
	mode := p.MixMode()
	for round := 0; round < rounds; round++ {
		switch mode {
		case 1:
			block := int(p.MixBlock())
			if block == 0 {
				block = 1
			}
			nblocks := minlen / block
			for bi := round & 1; bi < nblocks; bi += 2 {
				base := block * bi
				for k := 0; k < block; k++ {
					r1[base+k], r2[base+k] = r2[base+k], r1[base+k]
				}
			}
		case 0, 2:
			step := (round % 3) + int(p.MixInterval())
			if step == 0 {
				step = 1
			}
			off := int(p.MixOffset()) % step
			if mode == 2 {
				// sub_38D00(ctx+96, domain=3, index=chunkIdx, konst=round)
				// = prf32(routeDomain(3)=ss@96, kind=3, konst=chunkIdx, index=round).
				// [OK: disasm @0x395b0] off = (uint32)(MixOffset + prf) % step — the
				// binary's `(unsigned int)` cast wraps the add at 2^32 before the mod.
				prf := runtimePRF(p.seed64(96), 3, chunkIdx, uint32(round))
				off = int(uint32(p.MixOffset())+prf) % step
			}
			for pos := off; pos < minlen; pos += step {
				r1[pos], r2[pos] = r2[pos], r1[pos]
			}
		}
	}
}
