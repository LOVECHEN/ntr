package snellv6

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// const24 = byte_4A2960, the domain-separation prefix hashed before the PSK. [OK]
var const24 = []byte{
	0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94,
	0x33, 0x18, 0xc0, 0x6e, 0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
}

// MasterSeed = BLAKE2b-256(const24 || PSK), returned as 4 little-endian u64
// words (the form the profile builder consumes). [OK] (sub_39D90 / sub_1D2A60)
func MasterSeed(psk []byte) [4]uint64 {
	h, _ := blake2b.New(32, nil) // unkeyed, 32-byte digest
	h.Write(const24)
	h.Write(psk)
	sum := h.Sum(nil)
	var ms [4]uint64
	for i := 0; i < 4; i++ {
		ms[i] = binary.LittleEndian.Uint64(sum[i*8:])
	}
	return ms
}

// --- session key schedule (sub_39A90 -> sub_1D3490) ------------------------
//
// [SOLVED] The session-key KDF is STANDARD Argon2id, version 0x13, with the
// fixed protocol parameters t=3, m=8 KiB, p=1 (no secret, no associated data).
// The earlier "custom escrypt/yescrypt" read was wrong: the fBlaMka G-function,
// the blake2b_long variable-length hash (sub_1DCBD0), and the H0 initial hash
// (sub_1DABD0: BLAKE2b over LE32(lanes,taglen,m,t,version=0x13,type,...)) are
// all stock Argon2. Confirmed bit-exact against the golden vector:
//
//	argon2id(pass="0123456789abcdef", salt=00..0f, t=3, m=8, p=1, len=32)
//	  == b1113799efdfa051f080dd1be8d4855bc8b141224c325ac55ba5140261d14f99
//
// Mapping from the IDA dispatcher sub_1D3490(out,32,psk,16,salt,3,0x2000,2):
//
//	arg5=3   -> t_cost (iterations)
//	arg6=0x2000 bytes (=8 KiB) -> m_cost; escrypt_entry takes it pre-divided as 8
//	arg7=2   -> Argon2 type 2 = Argon2id
//	password = the raw PSK bytes; salt = the 16-byte per-connection salt.
const (
	argonTime     = 3 // t_cost
	argonMemKiB   = 8 // m_cost in KiB (== 8 blocks of 1024B; mmap was 8192B)
	argonLanes    = 1 // p
	sessionKeyLen = 32
)

// SessionKey derives the 32-byte session key with Argon2id, matching Snell v6.
func SessionKey(psk, salt []byte) ([]byte, error) {
	return argon2.IDKey(psk, salt, argonTime, argonMemKiB, argonLanes, sessionKeyLen), nil
}

// NewAEAD builds the data-plane AEAD. v6 HARDCODES AES-128-GCM (literal cipher
// flag 1 at all four AEAD call sites in sub_3B020/sub_3B3F0); sub_6A430 only
// selects the AES-NI-accelerated vs software EVP method table for the SAME
// cipher (NID 895 = AES-128-GCM), NOT AES-vs-ChaCha. The ChaCha20-Poly1305 path
// below is retained for the v1 (ChaCha) and v4/v5 (AES/ChaCha config bit)
// framings; in v6 it is unreachable. Both are 12-byte nonce + 16-byte tag.
//
// keyMaterial is the 32-byte SessionKey output; AES-128 uses the first 16 bytes.
func NewAEAD(keyMaterial []byte, preferChaCha bool) (cipher.AEAD, error) {
	if preferChaCha {
		return chacha20poly1305.New(keyMaterial[:32])
	}
	block, err := aes.NewCipher(keyMaterial[:16]) // AES-128-GCM
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Nonce is the 12-byte little-endian counter used for both directions
// (separate counters), starting at 0 and incremented once per AEAD op. [OK]
// (sub_1D55D0 case 12)
type Nonce [12]byte

func (n *Nonce) Bytes() []byte { return n[:] }

func (n *Nonce) Inc() {
	lo := binary.LittleEndian.Uint64(n[0:8])
	hi := binary.LittleEndian.Uint32(n[8:12])
	lo++
	if lo == 0 {
		hi++
	}
	binary.LittleEndian.PutUint64(n[0:8], lo)
	binary.LittleEndian.PutUint32(n[8:12], hi)
}
