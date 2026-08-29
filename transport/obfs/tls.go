// simple-obfs 的 TLS 伪装(mode=tls)。把流量伪装成 TLS 1.2 握手 + application-data 记录:
// 客户端首包发一个假 ClientHello,真实首段数据藏在 session-ticket 扩展里;服务端回假
// ServerHello + ChangeCipherSpec,真实首段数据跟在一条假 handshake 记录后;之后双向都用
// 假的 application-data 记录(0x17 0x03 0x03 <len> <data>)封装,16KB 一分片。
//
// ★线格式逐字节对齐 mihomo transport/simple-obfs 与 sing-box obfs-local(tls),自研纯 Go、
// 不改任何字节。占 Frame band,叠法同 http 模式:[obfs(tls), shadowsocks]。
package obfs

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
)

const tlsChunkSize = 1 << 14 // 16KiB:每条 application-data 记录的最大载荷

// ---------- 客户端 ----------

type tlsClientConn struct {
	link.Stream
	server        string
	remain        int
	firstRequest  bool
	firstResponse bool
}

var _ link.Stream = (*tlsClientConn)(nil)

func (c *tlsClientConn) Write(b []byte) (int, error) {
	total := len(b)
	for i := 0; i < total; i += tlsChunkSize {
		end := i + tlsChunkSize
		if end > total {
			end = total
		}
		if _, err := c.writeChunk(b[i:end]); err != nil {
			return i, err
		}
	}
	return total, nil
}

func (c *tlsClientConn) writeChunk(b []byte) (int, error) {
	if c.firstRequest {
		c.firstRequest = false
		if _, err := c.Stream.Write(makeClientHelloMsg(b, c.server)); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return len(b), writeAppData(c.Stream, b)
}

func (c *tlsClientConn) Read(b []byte) (int, error) {
	if c.remain > 0 {
		return c.readRemain(b)
	}
	if c.firstResponse {
		c.firstResponse = false
		// 丢弃 ServerHello+CCS 前缀(type+ver+len+91 = 96 · type+ver+len+1 = 6 · type+ver = 3 → 105)。
		return c.readRecord(b, 105)
	}
	return c.readRecord(b, 3) // 后续:丢 type+ver(3),读 len(2)
}

func (c *tlsClientConn) Unwrap() any { return c.Stream }

// ---------- 服务端 ----------

type tlsServerConn struct {
	link.Stream
	remain            int
	firstRequest      bool
	sessionTicketDone bool
	firstResponse     bool
}

var _ link.Stream = (*tlsServerConn)(nil)

func (s *tlsServerConn) Read(b []byte) (int, error) {
	if s.remain > 0 {
		return s.readRemain(b)
	}
	if s.firstRequest {
		s.firstRequest = false
		// 读到 session-ticket 数据:丢弃 ClientHello 到 ticket 长度前(9*16-4 = 140),读 len(2) 取数据。
		return s.readRecord(b, 9*16-4)
	}
	if !s.sessionTicketDone {
		s.sessionTicketDone = true
		if err := s.skipOtherExts(); err != nil {
			return 0, err
		}
	}
	return s.readRecord(b, 3)
}

// skipOtherExts 跳过 SNI 与其余固定扩展(ClientHello 里 session-ticket 之后的部分)。
func (s *tlsServerConn) skipOtherExts() error {
	buf := make([]byte, 256)
	if _, err := s.readRecord(buf, 7); err != nil { // 丢 server_name ext 头 7 字节,读 host
		return err
	}
	_, err := io.ReadFull(s.Stream, buf[:4*16+2]) // 其余固定扩展 66 字节
	return err
}

func (s *tlsServerConn) Write(b []byte) (int, error) {
	total := len(b)
	for i := 0; i < total; i += tlsChunkSize {
		end := i + tlsChunkSize
		if end > total {
			end = total
		}
		if _, err := s.writeChunk(b[i:end]); err != nil {
			return i, err
		}
	}
	return total, nil
}

func (s *tlsServerConn) writeChunk(b []byte) (int, error) {
	if s.firstResponse {
		s.firstResponse = false
		if _, err := s.Stream.Write(makeServerHello(b)); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return len(b), writeAppData(s.Stream, b)
}

func (s *tlsServerConn) Unwrap() any { return s.Stream }

// ---------- 共用帧读写 ----------

// writeAppData 把 b 封成一条假 application-data 记录(0x17 0x03 0x03 <len16> <b>)。
func writeAppData(w link.Stream, b []byte) error {
	var hdr [5]byte
	hdr[0], hdr[1], hdr[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(hdr[3:], uint16(len(b)))
	if _, err := w.Write(append(hdr[:], b...)); err != nil {
		return err
	}
	return nil
}

// tlsRecordReader 抽象客户端/服务端共用的记录读取(两者结构体字段名一致,方法各挂一份薄封装)。
func readRecord(r link.Stream, b []byte, discardN int, remain *int) (int, error) {
	if discardN > 0 {
		if _, err := io.ReadFull(r, make([]byte, discardN)); err != nil {
			return 0, err
		}
	}
	var sz [2]byte
	if _, err := io.ReadFull(r, sz[:]); err != nil {
		return 0, nil // 对齐 mihomo:size 读失败吞掉返回 0(连接收尾)
	}
	length := int(binary.BigEndian.Uint16(sz[:]))
	if length > len(b) {
		n, err := r.Read(b)
		if err != nil {
			return n, err
		}
		*remain = length - n
		return n, nil
	}
	return io.ReadFull(r, b[:length])
}

func readRemain(r link.Stream, b []byte, remain *int) (int, error) {
	length := *remain
	if length > len(b) {
		length = len(b)
	}
	n, err := io.ReadFull(r, b[:length])
	*remain -= n
	return n, err
}

func (c *tlsClientConn) readRecord(b []byte, d int) (int, error) { return readRecord(c.Stream, b, d, &c.remain) }
func (c *tlsClientConn) readRemain(b []byte) (int, error)        { return readRemain(c.Stream, b, &c.remain) }
func (s *tlsServerConn) readRecord(b []byte, d int) (int, error) { return readRecord(s.Stream, b, d, &s.remain) }
func (s *tlsServerConn) readRemain(b []byte) (int, error)        { return readRemain(s.Stream, b, &s.remain) }

// ---------- ClientHello / ServerHello 构造(逐字节对齐 mihomo simple-obfs) ----------

func makeClientHelloMsg(data []byte, server string) []byte {
	random := make([]byte, 28)
	sessionID := make([]byte, 32)
	_, _ = rand.Read(random)
	_, _ = rand.Read(sessionID)

	buf := &bytes.Buffer{}
	// record: handshake, TLS 1.0, length
	buf.WriteByte(22)
	buf.Write([]byte{0x03, 0x01})
	length := uint16(212 + len(data) + len(server))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length & 0xff))

	// ClientHello, length, TLS 1.2
	buf.WriteByte(1)
	buf.WriteByte(0)
	binary.Write(buf, binary.BigEndian, uint16(208+len(data)+len(server)))
	buf.Write([]byte{0x03, 0x03})

	// random(time+28) + sid len + sid
	binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	buf.Write(random)
	buf.WriteByte(32)
	buf.Write(sessionID)

	// cipher suites
	buf.Write([]byte{0x00, 0x38})
	buf.Write([]byte{
		0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
		0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
		0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
		0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
	})

	// compression
	buf.Write([]byte{0x01, 0x00})

	// extensions length
	binary.Write(buf, binary.BigEndian, uint16(79+len(data)+len(server)))

	// session ticket(藏真实首段数据)
	buf.Write([]byte{0x00, 0x23})
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)

	// server name
	buf.Write([]byte{0x00, 0x00})
	binary.Write(buf, binary.BigEndian, uint16(len(server)+5))
	binary.Write(buf, binary.BigEndian, uint16(len(server)+3))
	buf.WriteByte(0)
	binary.Write(buf, binary.BigEndian, uint16(len(server)))
	buf.Write([]byte(server))

	// ec_point_formats
	buf.Write([]byte{0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02})
	// supported_groups
	buf.Write([]byte{0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18})
	// signature_algorithms
	buf.Write([]byte{
		0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05,
		0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
		0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
	})
	// encrypt_then_mac
	buf.Write([]byte{0x00, 0x16, 0x00, 0x00})
	// extended_master_secret
	buf.Write([]byte{0x00, 0x17, 0x00, 0x00})

	return buf.Bytes()
}

func makeServerHello(data []byte) []byte {
	randBytes := make([]byte, 28)
	sessionID := make([]byte, 32)
	_, _ = rand.Read(randBytes)
	_, _ = rand.Read(sessionID)

	buf := &bytes.Buffer{}
	buf.WriteByte(0x16)
	binary.Write(buf, binary.BigEndian, uint16(0x0301))
	binary.Write(buf, binary.BigEndian, uint16(91))
	buf.Write([]byte{2, 0, 0, 87, 0x03, 0x03})
	binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	buf.Write(randBytes)
	buf.WriteByte(32)
	buf.Write(sessionID)

	buf.Write([]byte{0xcc, 0xa8})       // cipher suite
	buf.WriteByte(0)                    // compression
	buf.Write([]byte{0x00, 0x00})       // ext len placeholder head
	buf.Write([]byte{0xff, 0x01, 0x00, 0x01, 0x00})
	buf.Write([]byte{0x00, 0x17, 0x00, 0x00})
	buf.Write([]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00})

	// ChangeCipherSpec
	buf.Write([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01})

	// 假 handshake 记录承载真实首段数据
	buf.Write([]byte{0x16, 0x03, 0x03})
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)

	return buf.Bytes()
}
