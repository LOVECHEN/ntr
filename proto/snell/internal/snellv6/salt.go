package snellv6

// Salt scatter / de-scatter for the v6 handshake prefix.
//
// The 16-byte connection salt is hidden inside a `prefix_len`-byte random
// prefix region (the handshake area). 16 positions within `prefix_len+16`
// bytes are chosen by a Fisher-Yates permutation seeded from the profile; the
// salt byte at each chosen position is XOR-masked by a per-index keystream.
//
// Functions are byte-exact ports of sub_3AB70 (permutation), sub_38E50
// (keystream), sub_3AC50 (decode) and sub_3AE10 (encode).

// fisherYatesPerm reproduces sub_3AB70: an identity permutation of n entries
// (entries stored as bytes, so values wrap mod 256 exactly as the binary does),
// shuffled `rounds` times. Returns the full permutation; callers use perm[:16].
func fisherYatesPerm(seed uint64, rounds uint8, n int) []byte {
	perm := make([]byte, n)
	for i := 0; i < n; i++ {
		perm[i] = byte(i) // (_BYTE)v4 — truncates for n>256, matching the binary
	}
	if n == 0 {
		return perm
	}
	r := int(rounds)
	if r == 0 {
		r = 1 // *a2 ? *a2 : 1
	}
	for round := 0; round < r; round++ {
		konst := uint32(round) + 20903
		for pos := 0; pos < n; pos++ {
			idx := prfShuffle(seed, konst, uint32(pos))
			j := pos + int(idx%uint32(n-pos))
			perm[pos], perm[j] = perm[j], perm[pos]
		}
	}
	return perm
}

// saltKeystream reproduces sub_38E50: low byte of ((i*stride) ^ prf32(seed,2,20903,i)).
func saltKeystream(seed uint64, stride uint8, i int) byte {
	prf := prf32(seed, 2, 20903, uint32(i))
	return byte(uint32(uint8(i))*uint32(stride)) ^ byte(prf)
}

// DescatterSalt recovers the 16-byte salt from a handshake prefix region
// `inbuf` of length prefix_len+16 (sub_3AC50).
func (p *Profile) DescatterSalt(inbuf []byte) [16]byte {
	var salt [16]byte
	perm := fisherYatesPerm(p.SaltSeed(), p.SaltPermRounds(), len(inbuf))
	seed, stride := p.SaltSeed(), p.SaltMaskStride()
	for i := 0; i < 16; i++ {
		salt[i] = inbuf[perm[i]] ^ saltKeystream(seed, stride, i)
	}
	return salt
}

// ScatterSalt writes the 16-byte salt into `inbuf` (already filled with random
// padding) at the permuted positions (sub_3AE10). inbuf len = prefix_len+16.
func (p *Profile) ScatterSalt(inbuf []byte, salt [16]byte) {
	perm := fisherYatesPerm(p.SaltSeed(), p.SaltPermRounds(), len(inbuf))
	seed, stride := p.SaltSeed(), p.SaltMaskStride()
	for i := 0; i < 16; i++ {
		inbuf[perm[i]] = salt[i] ^ saltKeystream(seed, stride, i)
	}
}
