// Package codectest 提供跨协议共享的 codec 一致性 harness(承设计第 3 章 §3.4.1)。
// 协议包的 _test.go 用 RunConformance 跑三件事:decode==期望帧、encode==golden 字节
// (round-trip)、以及(建议另配)fuzz decode 不 panic/不越界。
package codectest

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/codec"
)

// Vector 是一条 golden 向量:期望帧 + 冻结的真实线字节。
type Vector struct {
	Name  string
	Frame any    // 应可断言为 codec 的 F 类型
	Wire  []byte // //go:embed testdata/*.bin 冻结的真实抓包
}

// Run 对每条向量断言 encode==golden 与 decode==frame(round-trip)。
// codec 包本身不 import testing;对拷 harness 隔离在本子包。
func Run[F any](t *testing.T, c codec.FrameCodec[F], vs []Vector) {
	t.Helper()
	for _, v := range vs {
		frame, ok := v.Frame.(F)
		if !ok {
			t.Fatalf("%s: Frame is %T, not the codec's frame type", v.Name, v.Frame)
		}

		// encode == golden bytes
		b := buf.New()
		if err := c.Encode(b, frame); err != nil {
			b.Release()
			t.Fatalf("%s: encode: %v", v.Name, err)
		}
		if !bytes.Equal(b.Bytes(), v.Wire) {
			got := append([]byte(nil), b.Bytes()...)
			b.Release()
			t.Fatalf("%s: encode mismatch\n got=%x\nwant=%x", v.Name, got, v.Wire)
		}
		b.Release()

		// decode(golden) == frame
		src := buf.As(append([]byte(nil), v.Wire...))
		got, err := c.Decode(src)
		if err != nil {
			t.Fatalf("%s: decode: %v", v.Name, err)
		}
		if !reflect.DeepEqual(got, frame) {
			t.Fatalf("%s: decode mismatch\n got=%#v\nwant=%#v", v.Name, got, frame)
		}
	}
}
