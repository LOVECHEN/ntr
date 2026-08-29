package ruleset

// succinct-trie 压缩域名集,mihomo .mrs 与 sing-box .srs 的 domain 载荷底层同构(openacid/succinct sskv):
// 三字段 leaves/labelBitmap/labels + rank/select 索引。两家匹配语义不同(mihomo 用 */+  通配、sing 用
// \r/\n 特殊标签),故共享位层 succinctBits,各自实现 MatchDomain。rank/select 索引本地重建(不入序列化)。

import (
	"math/bits"

	"github.com/LOVECHEN/ntr/rule"
)

// succinctBits 是共享位层:leaves/labelBitmap/labels + O(1) rank / 二分 select。
type succinctBits struct {
	leaves, labelBitmap []uint64
	labels              []byte
	wordOnes            []int32 // wordOnes[w]=labelBitmap[0..w) 的 1 数(前缀和),len=len(labelBitmap)+1
}

func newSuccinctBits(leaves, labelBitmap []uint64, labels []byte) *succinctBits {
	s := &succinctBits{leaves: leaves, labelBitmap: labelBitmap, labels: labels}
	s.wordOnes = make([]int32, len(labelBitmap)+1)
	for i, w := range labelBitmap {
		s.wordOnes[i+1] = s.wordOnes[i] + int32(bits.OnesCount64(w))
	}
	return s
}

func getBit(bm []uint64, i int) uint64 { return bm[i>>6] & (1 << uint(i&63)) }

// rank 返回 [0,i) 内 1 的个数。
func (s *succinctBits) rank(i int) int {
	w := i >> 6
	r := int(s.wordOnes[w])
	if b := uint(i & 63); b != 0 {
		r += bits.OnesCount64(s.labelBitmap[w] & ((uint64(1) << b) - 1))
	}
	return r
}

// countZeros 返回 [0,i) 内 0 的个数。
func (s *succinctBits) countZeros(i int) int { return i - s.rank(i) }

// selectIthOne 返回第 i 个 1 的下标(0 起)。二分定位 word 再扫位。
func (s *succinctBits) selectIthOne(i int) int {
	lo, hi := 0, len(s.labelBitmap)
	for lo < hi {
		mid := (lo + hi) / 2
		if int(s.wordOnes[mid+1]) <= i {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	remain := i - int(s.wordOnes[lo])
	x := s.labelBitmap[lo]
	for b := 0; b < 64; b++ {
		if x&(uint64(1)<<uint(b)) != 0 {
			if remain == 0 {
				return lo*64 + b
			}
			remain--
		}
	}
	return -1
}

// ── mihomo .mrs 匹配器(*/+  通配;逐位移植自 metacubex/mihomo component/trie DomainSet.Has) ──

const (
	complexWildcardByte = byte('+')
	wildcardByte        = byte('*')
	domainStepByte      = byte('.')
)

type mihomoDomainSet struct{ *succinctBits }

var _ rule.DomainSet = (*mihomoDomainSet)(nil)

func newSuccinctDomainSet(leaves, labelBitmap []uint64, labels []byte) *mihomoDomainSet {
	return &mihomoDomainSet{newSuccinctBits(leaves, labelBitmap, labels)}
}

func revLowerAt(key string, i int) byte {
	c := key[len(key)-1-i]
	if c >= 'A' && c <= 'Z' {
		c += 'a' - 'A'
	}
	return c
}

func byteReverse(s string) string {
	buf := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		buf[i] = s[len(s)-1-i]
	}
	return string(buf)
}

func reverseRunes(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func (m *mihomoDomainSet) MatchDomain(key string) bool {
	if m == nil {
		return false
	}
	s := m.succinctBits
	for i := 0; i < len(key); i++ {
		if key[i] >= 0x80 { // 非 ASCII:集合按 rune 反转建,故这里同样规范化再字节反转
			key = byteReverse(toLowerASCII(reverseRunes(key)))
			break
		}
	}
	nodeId, bmIdx := 0, 0
	type wildcardCursor struct{ bmIdx, index int }
	stack := make([]wildcardCursor, 0)
	for i := 0; i < len(key); i++ {
	RESTART:
		c := revLowerAt(key, i)
		for ; ; bmIdx++ {
			if getBit(s.labelBitmap, bmIdx) != 0 {
				if len(stack) > 0 {
					cursor := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					nextNodeId := s.countZeros(cursor.bmIdx + 1)
					nextBmIdx := s.selectIthOne(nextNodeId-1) + 1
					j := cursor.index
					for ; j < len(key) && revLowerAt(key, j) != domainStepByte; j++ {
					}
					if j == len(key) {
						if getBit(s.leaves, nextNodeId) != 0 {
							return true
						}
						goto RESTART
					}
					for ; nextBmIdx-nextNodeId < len(s.labels); nextBmIdx++ {
						if s.labels[nextBmIdx-nextNodeId] == domainStepByte {
							bmIdx = nextBmIdx
							nodeId = nextNodeId
							i = j
							goto RESTART
						}
					}
				}
				return false
			}
			if s.labels[bmIdx-nodeId] == complexWildcardByte {
				return true
			} else if s.labels[bmIdx-nodeId] == wildcardByte {
				stack = append(stack, wildcardCursor{bmIdx: bmIdx, index: i})
			} else if s.labels[bmIdx-nodeId] == c {
				break
			}
		}
		nodeId = s.countZeros(bmIdx + 1)
		bmIdx = s.selectIthOne(nodeId-1) + 1
	}
	return getBit(s.leaves, nodeId) != 0
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
