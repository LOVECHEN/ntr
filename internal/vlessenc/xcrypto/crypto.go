// Package crypto 是 vendored VLESS Encryption 对 xray common/crypto 的最小替身。
// 仅提供 RandBetween(vendored 代码构造 padding 用),语义与 xray 一致([from,to) 随机)。
package crypto

import (
	"crypto/rand"
	"math/big"
)

// RandBetween 返回 [from, to) 区间的随机整数(from==to 时返回 from),与 xray 逐字节一致。
func RandBetween(from int64, to int64) int64 {
	if from == to {
		return from
	}
	if from > to {
		from, to = to, from
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(to-from))
	return from + bigInt.Int64()
}
