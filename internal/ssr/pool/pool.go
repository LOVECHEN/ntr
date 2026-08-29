// Package pool 是 vendored SSR 代码对 mihomo common/pool 的最小替身。
// 仅提供 vendored 代码用到的 5 个入口:Get/Put(定长 []byte 复用)、GetBuffer/PutBuffer
// (*bytes.Buffer 复用)、RelayBufferSize 常量。语义与 mihomo 一致:Get(n) 返回长度恰为 n 的切片。
// 这些只影响内存复用,不触碰任何线格式字节。
package pool

import (
	"bytes"
	"sync"
)

// RelayBufferSize 是 TCP 中继缓冲上限(仅决定单次 io.Copy 的分块大小,不影响协议字节)。
const RelayBufferSize = 20 * 1024

var bytePool = sync.Pool{New: func() any { return new([]byte) }}

// Get 返回长度恰为 size 的切片(底层容量可能更大,已复用)。
func Get(size int) []byte {
	p := bytePool.Get().(*[]byte)
	if cap(*p) < size {
		*p = make([]byte, size)
	}
	return (*p)[:size]
}

// Put 归还切片。返回 error 仅为兼容 mihomo 签名,恒 nil。
func Put(buf []byte) error {
	if cap(buf) == 0 {
		return nil
	}
	b := buf[:cap(buf)]
	bytePool.Put(&b)
	return nil
}

var bufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// GetBuffer 取一个已 Reset 的 *bytes.Buffer。
func GetBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

// PutBuffer Reset 后归还。
func PutBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufferPool.Put(buf)
}
