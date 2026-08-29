package naive

import (
	"encoding/binary"
	"io"
	"math/rand"
)

// paddingCount 是带 padding 的前 N 个读/写包数(naive 线格式固定 8)。
const paddingCount = 8

// paddingHeaderChars 是 Padding HTTP 头的随机字符集(前 16 字节从中取,其余填 '~')。
const paddingHeaderChars = "!#$()+<>?@[]^`{}"

// generatePaddingHeader 生成 naive 的 `Padding` HTTP 头值:长 30–61,前 16 字节取自
// paddingHeaderChars,其余 '~'。请求与响应都必须带非空 Padding 头,否则对端判为非 naive。
func generatePaddingHeader() string {
	paddingLen := rand.Intn(32) + 30
	padding := make([]byte, paddingLen)
	bits := rand.Uint64()
	for i := 0; i < 16; i++ {
		padding[i] = paddingHeaderChars[bits&15]
		bits >>= 4
	}
	for i := 16; i < paddingLen; i++ {
		padding[i] = '~'
	}
	return string(padding)
}

// paddingConn 是 naive 的填充状态机:前 paddingCount 个包按
// [2B BE 原始数据长][1B padding 长][data][padding] 收发,之后转为裸字节流。
type paddingConn struct {
	readPadding      int
	writePadding     int
	readRemaining    int // 当前包剩余未读的原始数据
	paddingRemaining int // 当前包剩余待跳过的 padding
}

// read 按填充协议从 reader 读一段原始数据。
func (p *paddingConn) read(reader io.Reader, buffer []byte) (n int, err error) {
	if p.readRemaining > 0 { // 上个包的数据没读完,先读完
		if len(buffer) > p.readRemaining {
			buffer = buffer[:p.readRemaining]
		}
		n, err = reader.Read(buffer)
		if err != nil {
			return
		}
		p.readRemaining -= n
		return
	}
	if p.paddingRemaining > 0 { // 数据读完了,跳掉尾部 padding
		if _, err = io.CopyN(io.Discard, reader, int64(p.paddingRemaining)); err != nil {
			return
		}
		p.paddingRemaining = 0
	}
	if p.readPadding < paddingCount {
		var header []byte
		if len(buffer) >= 3 {
			header = buffer[:3] // 借用调用方缓冲,免分配(随后会被数据覆盖)
		} else {
			header = make([]byte, 3)
		}
		if _, err = io.ReadFull(reader, header); err != nil {
			return
		}
		dataSize := int(binary.BigEndian.Uint16(header[:2]))
		padSize := int(header[2])
		if len(buffer) > dataSize {
			buffer = buffer[:dataSize]
		}
		n, err = reader.Read(buffer)
		if err != nil {
			return
		}
		p.readPadding++
		p.readRemaining = dataSize - n
		p.paddingRemaining = padSize
		return
	}
	return reader.Read(buffer) // padding 阶段已过,裸流
}

// writeOne 按填充协议写一段 ≤65535 的数据。
func (p *paddingConn) writeOne(writer io.Writer, data []byte) (n int, err error) {
	if p.writePadding < paddingCount {
		padSize := rand.Intn(256)
		frame := make([]byte, 3+len(data)+padSize)
		binary.BigEndian.PutUint16(frame[:2], uint16(len(data)))
		frame[2] = byte(padSize)
		copy(frame[3:], data)
		// frame 尾部 padSize 字节保持零值(naive 不校验 padding 内容)
		if _, err = writer.Write(frame); err != nil {
			return 0, err
		}
		p.writePadding++
		return len(data), nil
	}
	return writer.Write(data)
}

// write 写一段任意长数据,超 65535 自动切块(padding 头的长度字段是 uint16)。
func (p *paddingConn) write(writer io.Writer, data []byte) (n int, err error) {
	for len(data) > 0 {
		chunk := data
		if len(chunk) > 65535 {
			chunk = chunk[:65535]
		}
		data = data[len(chunk):]
		var written int
		written, err = p.writeOne(writer, chunk)
		n += written
		if err != nil {
			return
		}
	}
	return
}
