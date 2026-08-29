package obfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"net"

	"github.com/LOVECHEN/ntr/internal/ssr/ntp"

	"github.com/metacubex/randv2"
)

var (
	errHTTPSimpleHead = errors.New("ssr: http_simple 首包头无效")
	errTLSMagic       = errors.New("ssr: tls1.2_ticket_auth 记录魔数错")
)

// PickServerObfs 建服务端 obfs 逆向包装。plain 由调用方透传;当前额外支持 http_simple / http_post /
// random_head / tls1.2_ticket_auth(+ fastauth)。key = SSR cipher 密钥(tls obfs 的 hmac 用)。
func PickServerObfs(name string, c net.Conn, key []byte) (net.Conn, error) {
	switch name {
	case "http_simple", "http_post":
		// 服务端解析 METHOD-无关(按空格切首行取 path),GET/POST 同一逆向。
		return &serverHTTPConn{Conn: c}, nil
	case "random_head":
		return &serverRandomHeadConn{Conn: c}, nil
	case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
		return &serverTLSTicketConn{Conn: c, key: key}, nil
	default:
		return nil, fmt.Errorf("ssr: 服务端暂不支持 obfs %q", name)
	}
}

// serverTLSTicketConn 是 tls1.2_ticket_auth 的服务端侧(镜像客户端 tls12TicketConn,照参考 Python
// obfs_tls.py 的 server_encode/server_decode):
//   - 首 Read 读客户端伪 ClientHello,提 sessionID(=clientID,hmac 密钥料),回发伪 ServerHello +
//     ChangeCipherSpec + Finished(两道 hmac 让客户端 Read 通过);之后读 CCS+Finished,再解 app-data 记录。
//   - Write 把数据裹进 [0x17,3,3][len][data] TLS app-data 记录。
// hmac 用 HmacSHA1(key + clientID, data)[:10]。
type serverTLSTicketConn struct {
	net.Conn
	key      []byte
	clientID []byte
	status   int // 0=待 ClientHello, 1=待 CCS+Finished, 8=app-data
	recvBuf  []byte
	decoded  []byte
}

func (c *serverTLSTicketConn) hmac10(data []byte) []byte {
	k := make([]byte, 0, len(c.key)+len(c.clientID))
	k = append(k, c.key...)
	k = append(k, c.clientID...)
	h := hmac.New(sha1.New, k)
	h.Write(data)
	return h.Sum(nil)[:10]
}

func (c *serverTLSTicketConn) Read(b []byte) (int, error) {
	for {
		if len(c.decoded) > 0 {
			n := copy(b, c.decoded)
			c.decoded = c.decoded[n:]
			return n, nil
		}
		if c.status == 8 {
			if c.unwrapAppData() && len(c.decoded) > 0 {
				continue
			}
		}
		tmp := make([]byte, 8192)
		n, err := c.Conn.Read(tmp)
		if err != nil {
			return 0, err
		}
		c.recvBuf = append(c.recvBuf, tmp[:n]...)
		if c.status == 0 {
			done, err := c.tryClientHello()
			if err != nil {
				return 0, err
			}
			if !done {
				continue
			}
		}
		if c.status == 1 {
			if !c.tryCCSFinished() {
				continue
			}
		}
		if c.status == 8 {
			c.unwrapAppData()
		}
	}
}

// tryClientHello 解客户端伪 ClientHello,提 clientID(sessionID),回发伪 ServerHello+CCS+Finished。
func (c *serverTLSTicketConn) tryClientHello() (bool, error) {
	b := c.recvBuf
	if len(b) < 5 {
		return false, nil
	}
	if b[0] != 0x16 || b[1] != 0x03 || b[2] != 0x01 {
		return false, errTLSMagic
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recLen {
		return false, nil
	}
	// b[9:11]=[3,3],b[11:43]=verifyid(32),b[43]=sidLen,b[44:44+sidLen]=sessionID(=clientID)
	if 5+recLen < 44 || b[43] < 32 {
		return false, errors.New("ssr: tls ClientHello 过短")
	}
	c.clientID = append([]byte(nil), b[44:76]...)
	c.recvBuf = b[5+recLen:]
	c.status = 1
	if err := c.sendServerHello(); err != nil {
		return false, err
	}
	return true, nil
}

// sendServerHello 构造并发送伪 ServerHello + ChangeCipherSpec + Finished(照 Python server_encode)。
func (c *serverTLSTicketConn) sendServerHello() error {
	// server random = [utc(4)][rand(18)][hmac10(key+clientID, 前22)]
	var srv bytes.Buffer
	var ts [4]byte
	binary.BigEndian.PutUint32(ts[:], uint32(ntp.Now().Unix()))
	srv.Write(ts[:])
	r18 := make([]byte, 18)
	_, _ = rand.Read(r18)
	srv.Write(r18)
	srv.Write(c.hmac10(srv.Bytes()))

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(srv.Bytes())         // 32B server random
	body.WriteByte(0x20)            // sessionID len
	body.Write(c.clientID)          // 32B echo sessionID
	body.Write([]byte{0xc0, 0x2f, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00})

	var sh bytes.Buffer
	sh.Write([]byte{0x02, 0x00})
	_ = binary.Write(&sh, binary.BigEndian, uint16(body.Len()))
	sh.Write(body.Bytes())

	var rec bytes.Buffer
	rec.Write([]byte{0x16, 0x03, 0x03})
	_ = binary.Write(&rec, binary.BigEndian, uint16(sh.Len()))
	rec.Write(sh.Bytes())
	// ChangeCipherSpec
	rec.Write([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01})
	// Finished:[0x16,3,3][len=32][rand(22)];尾部再补 10B 全局 hmac
	rec.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x20})
	r22 := make([]byte, 22)
	_, _ = rand.Read(r22)
	rec.Write(r22)
	rec.Write(c.hmac10(rec.Bytes()))

	_, err := c.Conn.Write(rec.Bytes())
	return err
}

// tryCCSFinished 消费客户端 ChangeCipherSpec + Finished;成功后 status=8,剩余为 app-data。
func (c *serverTLSTicketConn) tryCCSFinished() bool {
	b := c.recvBuf
	if len(b) < 11 {
		return false
	}
	// [0x14,3,3,0,1,1] CCS + [0x16,3,3][len(2)] Finished 头
	finishedDataLen := int(binary.BigEndian.Uint16(b[9:11]))
	total := 6 + 5 + finishedDataLen // CCS(6) + Finished 头(5) + Finished 数据
	if len(b) < total {
		return false
	}
	c.recvBuf = b[total:]
	c.status = 8
	return true
}

// unwrapAppData 把 recvBuf 里完整的 [0x17,3,3][len][data] 记录剥成 decoded。返回是否推进。
func (c *serverTLSTicketConn) unwrapAppData() bool {
	moved := false
	for len(c.recvBuf) > 5 {
		if c.recvBuf[0] != 0x17 || c.recvBuf[1] != 0x03 || c.recvBuf[2] != 0x03 {
			return moved
		}
		size := int(binary.BigEndian.Uint16(c.recvBuf[3:5]))
		if len(c.recvBuf) < 5+size {
			return moved
		}
		c.decoded = append(c.decoded, c.recvBuf[5:5+size]...)
		c.recvBuf = c.recvBuf[5+size:]
		moved = true
	}
	return moved
}

func (c *serverTLSTicketConn) Write(b []byte) (int, error) {
	total := len(b)
	var out bytes.Buffer
	for len(b) > 0 {
		size := len(b)
		if size > 16384 {
			size = 16384
		}
		out.Write([]byte{0x17, 0x03, 0x03})
		_ = binary.Write(&out, binary.BigEndian, uint16(size))
		out.Write(b[:size])
		b = b[size:]
	}
	if _, err := c.Conn.Write(out.Bytes()); err != nil {
		return 0, err
	}
	return total, nil
}

// serverRandomHeadConn 是 random_head 的服务端侧:双向各先发一段 [随机数据][crc32] 头再裸流。
// 首 Read 弃客户端随机头并回发服务端随机头(客户端读到后才发真数据),之后裸流;Write 裸流。
type serverRandomHeadConn struct {
	net.Conn
	recvHead bool
}

func (c *serverRandomHeadConn) Read(b []byte) (int, error) {
	if c.recvHead {
		return c.Conn.Read(b)
	}
	tmp := make([]byte, 4096)
	if _, err := c.Conn.Read(tmp); err != nil { // 弃客户端随机头
		return 0, err
	}
	c.recvHead = true
	// 回发服务端随机头:[randData(4..99)][crc32 = 0xffffffff - CRC(randData)]
	dataLength := randv2.IntN(96) + 4
	head := make([]byte, dataLength+4)
	_, _ = rand.Read(head[:dataLength])
	binary.LittleEndian.PutUint32(head[dataLength:], 0xffffffff-crc32.ChecksumIEEE(head[:dataLength]))
	if _, err := c.Conn.Write(head); err != nil {
		return 0, err
	}
	return 0, nil // 真数据在后续 Read
}

// serverHTTPConn 是 http_simple 的服务端侧(客户端 httpConn 的镜像):
//   - Read(入站):解客户端伪 GET —— 读到 \r\n\r\n,把 URL path 的 %XX 序列 hex-解回首段数据,
//     \r\n\r\n 之后为裸数据;之后裸流透传。
//   - Write(回程):首写前置一条伪 HTTP 200 响应头(客户端 Read 只找 \r\n\r\n 剥头),之后裸流。
type serverHTTPConn struct {
	net.Conn
	hasRecvHeader bool
	hasSentHeader bool
	pending       []byte // 已解出、待交付的数据
	accum         []byte // 头解析累积区
}

func (c *serverHTTPConn) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.hasRecvHeader {
		return c.Conn.Read(b)
	}
	tmp := make([]byte, 4096)
	for {
		n, err := c.Conn.Read(tmp)
		if err != nil {
			return 0, err
		}
		c.accum = append(c.accum, tmp[:n]...)
		pos := bytes.Index(c.accum, []byte("\r\n\r\n"))
		if pos == -1 {
			if len(c.accum) > 64*1024 {
				return 0, errHTTPSimpleHead
			}
			continue
		}
		headData, err := decodeHTTPSimpleHead(c.accum[:pos])
		if err != nil {
			return 0, err
		}
		decoded := append(headData, c.accum[pos+4:]...)
		c.hasRecvHeader = true
		c.accum = nil
		n2 := copy(b, decoded)
		if n2 < len(decoded) {
			c.pending = append(c.pending, decoded[n2:]...)
		}
		return n2, nil
	}
}

func (c *serverHTTPConn) Write(b []byte) (int, error) {
	if c.hasSentHeader {
		return c.Conn.Write(b)
	}
	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/html\r\n\r\n")
	buf.Write(b)
	if _, err := c.Conn.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	c.hasSentHeader = true
	return len(b), nil
}

// decodeHTTPSimpleHead 从伪请求头首行 "METHOD /%XX%XX... HTTP/1.1" 抽 path 并 hex-解回首段数据。
func decodeHTTPSimpleHead(header []byte) ([]byte, error) {
	line := header
	if i := bytes.IndexByte(line, '\r'); i != -1 {
		line = line[:i]
	}
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 == -1 {
		return nil, errHTTPSimpleHead
	}
	rest := line[sp1+1:]
	sp2 := bytes.IndexByte(rest, ' ')
	if sp2 == -1 {
		return nil, errHTTPSimpleHead
	}
	path := rest[:sp2]
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	out := make([]byte, 0, len(path)/3)
	for i := 0; i < len(path); {
		if path[i] != '%' || i+3 > len(path) {
			return nil, errHTTPSimpleHead
		}
		bt, err := hex.DecodeString(string(path[i+1 : i+3]))
		if err != nil {
			return nil, errHTTPSimpleHead
		}
		out = append(out, bt...)
		i += 3
	}
	return out, nil
}
