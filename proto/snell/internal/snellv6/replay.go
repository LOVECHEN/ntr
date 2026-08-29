package snellv6

import "sync"

// replayGuard rejects connections whose 16-byte handshake salt has been seen
// before (sub_4C0A0 lookup / sub_4C0F0 insert → "Session error E05"). The
// official structure is a COUNT-driven two-bank set, not time-based: a fixed
// capacity per bank (sub_4C020 derives dword_4ADB28 = 1000000/2 = 500000), salts
// inserted into the active bank, and when the active bank reaches capacity the
// active index flips and the new active bank is cleared (sub_4BFE0 memset) —
// keeping the just-filled bank as history. Lookups check both banks. There is
// no TTL / time component.
type replayGuard struct {
	mu       sync.Mutex
	banks    [2]map[[16]byte]struct{}
	active   int
	count    int // distinct inserts into the active bank
	capacity int // dword_4ADB28 = 500000
}

func newReplayGuard() *replayGuard {
	return &replayGuard{
		banks:    [2]map[[16]byte]struct{}{{}, {}},
		capacity: 500000,
	}
}

// seenBefore records salt and reports whether it was already present (a replay).
func (g *replayGuard) seenBefore(salt [16]byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.banks[g.active][salt]; ok {
		return true
	}
	if _, ok := g.banks[1-g.active][salt]; ok {
		return true
	}
	g.banks[g.active][salt] = struct{}{}
	g.count++
	if g.count >= g.capacity { // active bank full: flip + clear new active
		g.active = 1 - g.active
		g.banks[g.active] = make(map[[16]byte]struct{})
		g.count = 0
	}
	return false
}
