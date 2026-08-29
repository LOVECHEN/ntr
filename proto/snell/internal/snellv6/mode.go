package snellv6

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// Mode selects the v6.0.0b3 encryption mode (config key `mode`, parser sub_3B5E0;
// stored per framing state at offset 0x154 and dispatched in the encoder
// sub_3BD00 / decoder sub_3B6F0).
type Mode int

const (
	ModeDefault   Mode = iota // 0: traffic obfuscation (splitmix64 scatter+padding+mix) + AEAD
	ModeUnshaped              // 1: AEAD only, no obfuscation (random-looking ciphertext, ~v3)
	ModeUnsafeRaw             // 2: plaintext, no encryption, no obfuscation
)

func (m Mode) String() string {
	switch m {
	case ModeUnshaped:
		return "unshaped"
	case ModeUnsafeRaw:
		return "unsafe-raw"
	default:
		return "default"
	}
}

// ParseMode maps the config token to the enum (sub_3B5E0). The official uses
// strcasecmp, so matching is CASE-INSENSITIVE. ok=false for any unrecognized
// value — INCLUDING the empty string — for which the official logs
// "Parameter 'mode' should be one of: default, unshaped, unsafe-raw" and
// exit(1)s. An ABSENT key is not parsed at all and defaults to ModeDefault, so
// callers must only invoke ParseMode when the `mode` key is actually present.
func ParseMode(s string) (Mode, bool) {
	switch {
	case strings.EqualFold(s, "default"):
		return ModeDefault, true
	case strings.EqualFold(s, "unshaped"):
		return ModeUnshaped, true
	case strings.EqualFold(s, "unsafe-raw"):
		return ModeUnsafeRaw, true
	default:
		return ModeDefault, false
	}
}

// maxModeChunk is the fixed split size for unshaped/unsafe-raw (sub_3C520 /
// sub_3BFB0 both clamp each chunk to 0x3FFF). The default mode instead uses the
// PSK-derived chunk-size schedule.
const maxModeChunk = 0x3FFF

// All three modes share the same 7-byte logical chunk header
//
//	[0x04][00 00][padlen u16 BE][datalen u16 BE]
//
// In unshaped/unsafe-raw padlen is always 0 (no padding region).

// validModeHeader enforces the strict header check both b3 mode decoders apply
// (sub_3CA50 lines 4326-4328 / sub_3C1A0 lines 3930-3932): exactly 7 bytes,
// hdr[0]==4, and BOTH the reserved u16 (hdr[1:3]) and the padlen u16 (hdr[3:5])
// must be zero. A nonzero byte anywhere in hdr[1:5] is rejected as a bad frame.
func validModeHeader(hdr []byte) bool {
	return len(hdr) == 7 && hdr[0] == 4 &&
		hdr[1] == 0 && hdr[2] == 0 && hdr[3] == 0 && hdr[4] == 0
}

// --- unshaped (mode 1): salt + AEAD header + AEAD payload, no obfuscation -----

// encodeUnshaped frames payload as the unshaped mode (sub_3C520): the first chunk
// emits a 16-byte PLAINTEXT salt (not scattered) and derives the Argon2id key;
// every chunk then emits AEAD(7B header) followed by AEAD(payload), both with an
// EMPTY AAD and a per-AEAD-op nonce increment. There is no prepad/postpad/mix.
func (s *Sender) encodeUnshaped(payload []byte) ([]byte, error) {
	if len(payload) <= maxModeChunk {
		return s.unshapedOne(payload)
	}
	var out []byte
	for off := 0; off < len(payload); off += maxModeChunk {
		n := min(len(payload)-off, maxModeChunk)
		c, err := s.unshapedOne(payload[off : off+n])
		if err != nil {
			return nil, err
		}
		out = append(out, c...)
	}
	return out, nil
}

func (s *Sender) unshapedOne(payload []byte) ([]byte, error) {
	var out []byte
	if !s.started {
		if _, err := rand.Read(s.salt[:]); err != nil {
			return nil, err
		}
		key, err := SessionKey(s.psk, s.salt[:])
		if err != nil {
			return nil, err
		}
		if s.aead, err = NewAEAD(key, s.chacha); err != nil {
			return nil, err
		}
		s.nonce = Nonce{}
		out = append(out, s.salt[:]...) // plaintext salt, no scatter
		s.started = true
	}
	var hdr [7]byte
	hdr[0] = 4 // padlen (hdr[3:5]) stays 0
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))
	out = append(out, s.aead.Seal(nil, s.nonce[:], hdr[:], nil)...)
	s.nonce.Inc()
	if len(payload) > 0 {
		out = append(out, s.aead.Seal(nil, s.nonce[:], payload, nil)...)
		s.nonce.Inc()
	}
	s.idx++
	return out, nil
}

// decodeUnshaped reads one unshaped chunk (sub_3CA50).
func (r *Receiver) decodeUnshaped(rd io.Reader) ([]byte, error) {
	if !r.started {
		if _, err := io.ReadFull(rd, r.salt[:]); err != nil {
			return nil, err
		}
		key, err := SessionKey(r.psk, r.salt[:])
		if err != nil {
			return nil, err
		}
		encHdr := make([]byte, 23)
		if _, err := io.ReadFull(rd, encHdr); err != nil {
			return nil, err
		}
		for _, useChaCha := range []bool{false, true} {
			aead, e := NewAEAD(key, useChaCha)
			if e != nil {
				continue
			}
			pt, e := aead.Open(nil, r.nonce[:], encHdr, nil)
			if e == nil && validModeHeader(pt) {
				r.aead = aead
				r.chacha = useChaCha
				r.started = true
				r.nonce.Inc()
				return r.finishUnshaped(rd, pt)
			}
		}
		return nil, errBadHeader
	}
	encHdr := make([]byte, 23)
	if _, err := io.ReadFull(rd, encHdr); err != nil {
		return nil, err
	}
	hdr, err := r.aead.Open(nil, r.nonce[:], encHdr, nil)
	if err != nil {
		return nil, err
	}
	if !validModeHeader(hdr) {
		return nil, errBadHeader
	}
	r.nonce.Inc()
	return r.finishUnshaped(rd, hdr)
}

func (r *Receiver) finishUnshaped(rd io.Reader, hdr []byte) ([]byte, error) {
	payloadLen := int(binary.BigEndian.Uint16(hdr[5:7]))
	r.lastPrepad, r.lastPostpad, r.lastPayload = 0, 0, payloadLen
	r.idx++
	if payloadLen == 0 {
		return []byte{}, nil
	}
	encPayload := make([]byte, payloadLen+16)
	if _, err := io.ReadFull(rd, encPayload); err != nil {
		return nil, err
	}
	payload, err := r.aead.Open(nil, r.nonce[:], encPayload, nil)
	if err != nil {
		return nil, err
	}
	r.nonce.Inc()
	return payload, nil
}

// --- unsafe-raw (mode 2): 7-byte header + plaintext, no salt/AEAD -------------

var errRawHeader = errors.New("snellv6: unsafe-raw header type check failed")

// encodeRaw frames payload as the unsafe-raw mode (sub_3BFB0): each ≤0x3FFF chunk
// is the 7-byte header followed by the verbatim plaintext. No salt, no AEAD.
func (s *Sender) encodeRaw(payload []byte) ([]byte, error) {
	s.started = true
	if len(payload) <= maxModeChunk {
		return rawOne(payload), nil
	}
	var out []byte
	for off := 0; off < len(payload); off += maxModeChunk {
		n := min(len(payload)-off, maxModeChunk)
		out = append(out, rawOne(payload[off:off+n])...)
	}
	return out, nil
}

func rawOne(payload []byte) []byte {
	out := make([]byte, 7+len(payload))
	out[0] = 4 // bytes 1..5 stay 0 (padlen=0)
	binary.BigEndian.PutUint16(out[5:7], uint16(len(payload)))
	copy(out[7:], payload)
	return out
}

// decodeRaw reads one unsafe-raw chunk (sub_3C1A0).
func (r *Receiver) decodeRaw(rd io.Reader) ([]byte, error) {
	r.started = true
	var hdr [7]byte
	if _, err := io.ReadFull(rd, hdr[:]); err != nil {
		return nil, err
	}
	if !validModeHeader(hdr[:]) {
		return nil, errRawHeader
	}
	payloadLen := int(binary.BigEndian.Uint16(hdr[5:7]))
	r.lastPrepad, r.lastPostpad, r.lastPayload = 0, 0, payloadLen
	if payloadLen == 0 {
		return []byte{}, nil
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(rd, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
