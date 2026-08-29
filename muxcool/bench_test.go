package muxcool

import (
	"bytes"
	"io"
	"testing"
)

// BenchmarkWriteData 量化回程数据帧写路径的分配(Bridge/Portal 每个数据 chunk 都过这里)。
func BenchmarkWriteData(b *testing.B) {
	data := make([]byte, 4096)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		if err := WriteData(io.Discard, 1, data); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriteNewTCP 量化 New(带地址)帧写路径分配。
func BenchmarkWriteNewTCP(b *testing.B) {
	m := &FrameMetadata{SessionID: 1, Status: StatusNew, Network: NetworkTCP,
		Address: AddrFromString("1.2.3.4"), Port: 80}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := WriteFrame(io.Discard, m, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReadFrame 量化数据帧读路径分配(每个入站帧都过 ReadFrame)。
func BenchmarkReadFrame(b *testing.B) {
	var buf bytes.Buffer
	if err := WriteData(&buf, 1, make([]byte, 4096)); err != nil {
		b.Fatal(err)
	}
	raw := buf.Bytes()
	r := bytes.NewReader(raw)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for i := 0; i < b.N; i++ {
		r.Reset(raw)
		if _, _, err := ReadFrame(r); err != nil {
			b.Fatal(err)
		}
	}
}
