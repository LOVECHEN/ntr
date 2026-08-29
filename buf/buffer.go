// Package buf 提供带 headroom/tailroom 的三段缓冲(承设计第 3 章 §3.6bis 拷贝纪律)。
//
// 各层写协议头/尾时向预留区扩展,不重新分配、不搬移载荷;AEAD 就地开封/密封靠
// 同一块内存。缓冲从 sync.Pool 取,免分配(中继路径 AllocsPerRun 目标为 0)。
package buf

import (
	"errors"
	"sync"
)

const (
	// DefaultSize 是池化缓冲底层数组大小。对齐 runtime size class(32KiB)。
	DefaultSize = 32 * 1024
	// DefaultHeadroom 预留给协议头 / AEAD nonce 的前部空间。
	DefaultHeadroom = 512
)

// ErrShortBuffer 表示写入超出底层容量(tailroom 不足)。
var ErrShortBuffer = errors.New("buf: short buffer")

// Buffer 是带 headroom / tailroom 的三段结构:
//
//	[0,start)   headroom  —— 供 ExtendHeader 向前扩(写头)
//	[start,end) 载荷        —— Bytes() 返回这一段
//	[end,cap)   tailroom  —— 供 ExtendTail 向后扩(写尾)
//
// 零值不可用;用 New()(池化)或 As()(包裹现成字节)。
type Buffer struct {
	data       []byte
	start, end int
	pooled     bool
}

var pool = sync.Pool{New: func() any { return &Buffer{data: make([]byte, DefaultSize)} }}

// New 从池取一个缓冲,载荷区从 DefaultHeadroom 起(预留头部)。用完必须 Release。
func New() *Buffer {
	b := pool.Get().(*Buffer)
	b.start = DefaultHeadroom
	b.end = DefaultHeadroom
	b.pooled = true
	return b
}

// As 用现成字节包一个非池化缓冲(载荷 = 全部,无 headroom)。Release 是空操作。
func As(p []byte) *Buffer { return &Buffer{data: p, start: 0, end: len(p)} }

// Release 归还池化缓冲;非池化的忽略。归还后不得再用。
func (b *Buffer) Release() {
	if b == nil || !b.pooled {
		return
	}
	b.start, b.end, b.pooled = 0, 0, false
	pool.Put(b)
}

// Bytes 返回当前载荷([start,end))。
func (b *Buffer) Bytes() []byte { return b.data[b.start:b.end] }

// Len 返回载荷长度。
func (b *Buffer) Len() int { return b.end - b.start }

// Cap 返回底层数组容量。
func (b *Buffer) Cap() int { return len(b.data) }

// Headroom 返回当前可向前扩的字节数。
func (b *Buffer) Headroom() int { return b.start }

// Tailroom 返回当前可向后扩的字节数。
func (b *Buffer) Tailroom() int { return len(b.data) - b.end }

// Reset 清空载荷,把载荷区重置到默认 headroom 处(池化缓冲复用时用)。
func (b *Buffer) Reset() { b.start, b.end = DefaultHeadroom, DefaultHeadroom }

// ExtendHeader 向前扩 n 字节(写协议头 / AEAD nonce),返回可写切片。不拷贝、不搬载荷。
// 前置条件:Headroom() >= n(装配期静态预留;不足是编程错误,会越界 panic)。
func (b *Buffer) ExtendHeader(n int) []byte {
	b.start -= n
	return b.data[b.start : b.start+n]
}

// ExtendTail 向后扩 n 字节(写 AEAD tag / padding),返回可写切片。不拷贝。
// 前置条件:Tailroom() >= n。
func (b *Buffer) ExtendTail(n int) []byte {
	s := b.end
	b.end += n
	return b.data[s:b.end]
}

// Advance 前移载荷起点 n 字节(剥掉已消费的头部,如剥协议头)。切片重定位,不搬字节。
func (b *Buffer) Advance(n int) { b.start += n }

// Truncate 把载荷截到 n 字节。
func (b *Buffer) Truncate(n int) { b.end = b.start + n }

// Write 追加到载荷尾部。tailroom 不足时写入部分并返回 ErrShortBuffer。
func (b *Buffer) Write(p []byte) (int, error) {
	n := copy(b.data[b.end:], p)
	b.end += n
	if n < len(p) {
		return n, ErrShortBuffer
	}
	return n, nil
}

// WriteByte 追加一个字节。
func (b *Buffer) WriteByte(c byte) error {
	if b.Tailroom() < 1 {
		return ErrShortBuffer
	}
	b.data[b.end] = c
	b.end++
	return nil
}
