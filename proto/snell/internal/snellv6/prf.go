// Package snellv6 is a clean-room-from-RE reference implementation of the
// Snell v6 (v6.0.0b2) deployment-profile / transport layer, for porting.
//
// Status of each primitive is annotated:
//
//	[OK]   bit-exact, confirmed from disassembly
//	[CAL]  structure confirmed, exact wiring to be CALIBRATED against the
//	       golden vectors in testdata/ (run the real binary, diff)
//
// All 64-bit arithmetic is intentionally wrapping (Go uint64 wraps on overflow).
package snellv6

import "math/bits"

// ---- SplitMix64 finalizer (sub_38B70) ------------------------------- [OK]
func fmix64(x uint64) uint64 {
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

// ---- field PRF (sub_38C90) ------------------------------------------ [OK]
// Returns a 32-bit pseudo-random value from a per-domain seed and three
// mixing inputs (a "kind", a domain-separation constant, and an index).
// Folded 64->32 as the binary does: hi32 ^ lo32.
func prf32(seed uint64, kind, konst, index uint32) uint32 {
	t := seed
	t ^= uint64(index)*0x589965CC75374CC3 + 0x33A213EC50FFE2E9
	t ^= uint64(kind) * 0x9E3779B97F4A7C15
	t ^= uint64(konst)*0xE7037ED1A0B428DB + 0x8F3907F7B2B80C35
	v := fmix64(t)
	return uint32(v>>32) ^ uint32(v)
}

// ---- runtime PRF (sub_38D00 -> sub_38C30 route -> sub_38C90) --------- [OK]
// Used for the on-the-wire length schedule (prefix/prepad/postpad). The arg
// routing differs from the field PRF: sub_38D00(seed,domain,idxArg,konstArg)
// lands in sub_38C90 as (a2=domain, a3=idxArg, a4=konstArg), i.e. prf32 with
// kind=domain, konst=idxArg, index=konstArg (verified by disasm of sub_38D00).
func runtimePRF(routedSeed uint64, domain, idxArg, konstArg uint32) uint32 {
	return prf32(routedSeed, domain, idxArg, konstArg)
}

// ---- per-domain sub-seed derivation (sub_38BB0) --------------------- [OK]
// ms = the four little-endian u64 words of the 32-byte BLAKE2b master seed.
func subSeed(ms [4]uint64, domain uint32, magic uint64) uint64 {
	x := uint64(domain) * 0xD6E8FEB86659FD93
	x ^= magic + 0xA0761D6478BD642F
	x ^= ms[0]
	x ^= ms[1] + 0x9E3779B97F4A7C15
	x ^= bits.RotateLeft64(ms[2], 17)
	x ^= bits.RotateLeft64(ms[3], -11) // ror 11
	return fmix64(x)
}

// ---- bounded range map (sub_38B30) ---------------------------------- [OK]
// Inclusive of both lo and hi.
func mapRange(prf uint32, lo, hi uint16) uint16 {
	if hi <= lo {
		return lo
	}
	return lo + uint16(prf%uint32(hi-lo+1))
}

// ---- shuffle PRF variant (sub_3AB10) -------------------------------- [OK]
// Used by the Fisher-Yates salt permutation. Note this variant has an extra
// fixed XOR constant and NO "kind" term (cf. prf32).
func prfShuffle(seed uint64, konst, index uint32) uint32 {
	t := seed
	t ^= 0xDAA66D2C7DDF743F
	t ^= uint64(index)*0x589965CC75374CC3 + 0x33A213EC50FFE2E9
	t ^= uint64(konst)*0xE7037ED1A0B428DB - 0x70C6F8084D47F3CB
	v := fmix64(t)
	return uint32(v>>32) ^ uint32(v)
}
