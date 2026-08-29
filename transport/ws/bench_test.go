package ws

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// BenchmarkWSWriteFrame:量化每帧写入的分配(客户端掩码路径,32KB payload = 中继典型块)。
func BenchmarkWSWriteFrame(b *testing.B) {
	payload := bytes.Repeat([]byte{0xAB}, 32*1024)
	c := &wsConn{Conn: nopConn{}, isClient: true}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := c.writeFrame(opBinary, payload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWSReadFrame:量化每帧读取的分配(服务端读客户端掩码帧)。
func BenchmarkWSReadFrame(b *testing.B) {
	payload := bytes.Repeat([]byte{0xAB}, 32*1024)
	var framed bytes.Buffer
	cw := &wsConn{Conn: writerConn{&framed}, isClient: true}
	_ = cw.writeFrame(opBinary, payload)
	one := framed.Bytes()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc := &wsConn{br: bufioReader(bytes.NewReader(one))}
		if _, _, err := rc.readFrame(); err != nil {
			b.Fatal(err)
		}
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Write(p []byte) (int, error) { return len(p), nil }

type writerConn struct{ w io.Writer }

func (writerConn) Unwrap() any                      { return nil }
func (w writerConn) Write(p []byte) (int, error)    { return w.w.Write(p) }
func (writerConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (writerConn) Close() error                     { return nil }
func (writerConn) LocalAddr() net.Addr              { return nil }
func (writerConn) RemoteAddr() net.Addr             { return nil }
func (writerConn) SetDeadline(t time.Time) error    { return nil }
func (writerConn) SetReadDeadline(time.Time) error  { return nil }
func (writerConn) SetWriteDeadline(time.Time) error { return nil }

func bufioReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }
