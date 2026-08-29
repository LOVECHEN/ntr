package mtproto

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
)

// faketls —— MTProto 的外层伪装(ee secret 模式):把流量封成合法的 TLS 1.3 记录,
// 握手阶段用真实的 ClientHello/ServerHello 外形,但 32 字节 random 兼作 HMAC 认证凭据。
//
// 分层:TCP → faketls 记录(17 03 03 len)→ obfuscated2(64B 帧 + AES-CTR)→ MTProto 载荷。
//
// 关键线格式:
//   - ClientHello 的 random 位于偏移 11(记录头 5 + 握手头 4 + client_version 2)。
//   - 客户端令 random = HMAC-SHA256(secret, 整帧但 random 位置填 32 个 0) XOR (28 字节 0 ‖ LE32(时间戳))。
//     服务端反算 HMAC XOR random,前 28 字节须全 0,后 4 字节小端解出时间戳做时钟偏移校验。
//   - ServerHello 回三段(ServerHello + ChangeCipherSpec + 一条 ApplicationData noise),
//     server random(同样在偏移 11)先置 0,对 clientRandom ‖ 整个三段包做 HMAC 后写回该位置。
//     ★ noise 必须【恰好一条】ApplicationData 记录,否则客户端算出的 HMAC 对不上。

const (
	recTypeChangeCipherSpec = 0x14
	recTypeHandshake        = 0x16
	recTypeApplicationData  = 0x17

	recHeaderLen          = 5 // type(1) + version(2) + length(2)
	maxRecordPayload      = 16384 - recHeaderLen
	tlsRandomOffset       = 11 // 记录头5 + 握手类型1 + uint24长度3 + client_version2
	tlsRandomLen          = 32
	greaseMask            = 0x0f0f
	greaseValue           = 0x0a0a
	defaultTimeSkew       = 90 * time.Second
	handshakeTypeHello    = 0x01
	handshakeTypeSrvHello = 0x02
)

// tlsVersion 是记录层与握手体统一使用的版本字节(TLS 1.2 表示,兼容 1.3)。
var tlsVersion = [2]byte{0x03, 0x03}

// serverHelloSuffix 是 ServerHello 里 session_id/cipher_suite 之后的固定 17 字节:
// 无压缩 + extensions(supported_versions=TLS1.3, key_share=x25519 32 字节公钥)。
var serverHelloSuffix = [...]byte{
	0x00,       // compression method = null
	0x00, 0x2e, // extensions 总长 46
	0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported_versions: TLS 1.3
	0x00, 0x33, 0x00, 0x24, // key_share, 长度 36
	0x00, 0x1d, // group = x25519
	0x00, 0x20, // 公钥长度 32
}

// changeCipherSpecRecord 是固定 6 字节的 ChangeCipherSpec 记录。
var changeCipherSpecRecord = [...]byte{recTypeChangeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01}

var (
	errBadDigest      = errors.New("mtproto/faketls: ClientHello digest 校验失败(secret 不符)")
	errTimeSkew       = errors.New("mtproto/faketls: 客户端时间偏移超出容差")
	errBadRecord      = errors.New("mtproto/faketls: TLS 记录格式非法")
	errNotClientHello = errors.New("mtproto/faketls: 不是 ClientHello")
	errRecordTooBig   = errors.New("mtproto/faketls: 记录载荷超长")
)

// clientHelloInfo 是从 ClientHello 提取的、合成 ServerHello 所需的信息。
type clientHelloInfo struct {
	raw         []byte // 完整 ClientHello 记录(含记录头)
	random      [tlsRandomLen]byte
	sessionID   []byte
	cipherSuite uint16
	sni         string // server_name 扩展里的 host_name(用于校验 domain fronting 主机名)
}

// writeRecord 把 payload 封成一条 ApplicationData 记录写出(超长自动切块)。
func writeRecord(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > maxRecordPayload {
			chunk = chunk[:maxRecordPayload]
		}
		payload = payload[len(chunk):]
		var hdr [recHeaderLen]byte
		hdr[0] = recTypeApplicationData
		hdr[1], hdr[2] = tlsVersion[0], tlsVersion[1]
		binary.BigEndian.PutUint16(hdr[3:5], uint16(len(chunk)))
		if _, err := w.Write(append(hdr[:], chunk...)); err != nil {
			return err
		}
	}
	return nil
}

// readRecord 读一条 TLS 记录,返回类型与载荷。
func readRecord(r io.Reader) (byte, []byte, error) {
	var hdr [recHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	if hdr[1] != tlsVersion[0] || hdr[2] != tlsVersion[1] {
		// 记录层版本 03 03;ClientHello 记录允许 03 01
		if !(hdr[0] == recTypeHandshake && hdr[1] == 0x03 && hdr[2] == 0x01) {
			return 0, nil, errBadRecord
		}
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > maxRecordPayload+recHeaderLen {
		return 0, nil, errRecordTooBig
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

// tlsConn 把一条已完成 faketls 握手的连接包成【双向都封 ApplicationData 记录】的流。
// 读侧静默跳过非 ApplicationData 记录(如 ChangeCipherSpec)。
type tlsConn struct {
	rw  io.ReadWriter
	br  *bufio.Reader
	buf bytes.Buffer
}

func newTLSConn(rw io.ReadWriter, br *bufio.Reader) *tlsConn {
	if br == nil {
		br = bufio.NewReader(rw)
	}
	return &tlsConn{rw: rw, br: br}
}

func (c *tlsConn) Read(p []byte) (int, error) {
	for {
		if c.buf.Len() > 0 {
			return c.buf.Read(p)
		}
		typ, payload, err := readRecord(c.br)
		if err != nil {
			return 0, err
		}
		if typ != recTypeApplicationData {
			continue // 跳过 ChangeCipherSpec 等
		}
		c.buf.Write(payload)
	}
}

func (c *tlsConn) Write(p []byte) (int, error) {
	if err := writeRecord(c.rw, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// parseClientHello 解析并规范化 ClientHello,提取 random / sessionID / 首个非 GREASE cipher suite。
func parseClientHello(br *bufio.Reader) (*clientHelloInfo, error) {
	var hdr [recHeaderLen]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != recTypeHandshake {
		return nil, errNotClientHello
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n < 4+2+tlsRandomLen+1 || n > maxRecordPayload {
		return nil, errBadRecord
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	if body[0] != handshakeTypeHello {
		return nil, errNotClientHello
	}
	raw := append(append(make([]byte, 0, recHeaderLen+n), hdr[:]...), body...)

	info := &clientHelloInfo{raw: raw}
	copy(info.random[:], raw[tlsRandomOffset:tlsRandomOffset+tlsRandomLen])

	// session_id
	p := tlsRandomOffset + tlsRandomLen
	if p >= len(raw) {
		return nil, errBadRecord
	}
	sl := int(raw[p])
	p++
	if p+sl > len(raw) {
		return nil, errBadRecord
	}
	info.sessionID = raw[p : p+sl]
	p += sl
	// cipher_suites:取首个非 GREASE
	if p+2 > len(raw) {
		return nil, errBadRecord
	}
	csLen := int(binary.BigEndian.Uint16(raw[p : p+2]))
	p += 2
	if p+csLen > len(raw) || csLen%2 != 0 {
		return nil, errBadRecord
	}
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(raw[p+i : p+i+2])
		if cs&greaseMask != greaseValue {
			info.cipherSuite = cs
			break
		}
	}
	if info.cipherSuite == 0 {
		return nil, errors.New("mtproto/faketls: 未找到非 GREASE cipher suite")
	}
	p += csLen
	// compression_methods
	if p >= len(raw) {
		return nil, errBadRecord
	}
	cml := int(raw[p])
	p += 1 + cml
	// extensions:找 server_name(type 0x0000)取 host_name
	if p+2 <= len(raw) {
		extTotal := int(binary.BigEndian.Uint16(raw[p : p+2]))
		p += 2
		end := p + extTotal
		if end > len(raw) {
			end = len(raw)
		}
		for p+4 <= end {
			etype := binary.BigEndian.Uint16(raw[p : p+2])
			elen := int(binary.BigEndian.Uint16(raw[p+2 : p+4]))
			p += 4
			if p+elen > end {
				break
			}
			if etype == 0x0000 { // server_name
				info.sni = parseSNI(raw[p : p+elen])
			}
			p += elen
		}
	}
	return info, nil
}

// parseSNI 从 server_name 扩展体里取第一个 host_name。
// 体结构:[2B list 长度][1B name_type=0][2B name 长度][name]…
func parseSNI(ext []byte) string {
	if len(ext) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(ext[:2]))
	p := 2
	end := p + listLen
	if end > len(ext) {
		end = len(ext)
	}
	for p+3 <= end {
		nameType := ext[p]
		nameLen := int(binary.BigEndian.Uint16(ext[p+1 : p+3]))
		p += 3
		if p+nameLen > end {
			break
		}
		if nameType == 0x00 {
			return string(ext[p : p+nameLen])
		}
		p += nameLen
	}
	return ""
}

// verifyClientHello 校验 digest:HMAC 覆盖「整帧但 random 位置替换成 32 个 0」,
// 结果 XOR 客户端 random 后前 28 字节须全 0,后 4 字节为小端 UNIX 秒时间戳。
func verifyClientHello(info *clientHelloInfo, secret []byte, skew time.Duration) error {
	mac := hmac.New(sha256.New, secret)
	mac.Write(info.raw[:tlsRandomOffset])
	var zeros [tlsRandomLen]byte
	mac.Write(zeros[:])
	mac.Write(info.raw[tlsRandomOffset+tlsRandomLen:])
	computed := mac.Sum(nil)

	for i := range tlsRandomLen {
		computed[i] ^= info.random[i]
	}
	if subtle.ConstantTimeCompare(zeros[:tlsRandomLen-4], computed[:tlsRandomLen-4]) != 1 {
		return errBadDigest
	}
	ts := int64(binary.LittleEndian.Uint32(computed[tlsRandomLen-4:]))
	if d := time.Since(time.Unix(ts, 0)); d < -skew || d > skew {
		return errTimeSkew
	}
	return nil
}

// buildServerHello 合成 ServerHello + ChangeCipherSpec + 一条 noise ApplicationData 三段包,
// 并把 HMAC(secret, clientRandom ‖ 整包[server random 置 0]) 写回 server random 位置(偏移 11)。
func buildServerHello(info *clientHelloInfo, secret []byte) ([]byte, error) {
	// 内层 handshake payload
	var inner bytes.Buffer
	inner.Write(tlsVersion[:])
	inner.Write(make([]byte, tlsRandomLen)) // server random 占位(先全 0)
	inner.WriteByte(byte(len(info.sessionID)))
	inner.Write(info.sessionID)
	var cs [2]byte
	binary.BigEndian.PutUint16(cs[:], info.cipherSuite)
	inner.Write(cs[:])
	inner.Write(serverHelloSuffix[:])
	// x25519 临时公钥(32 字节)
	var scalar [32]byte
	if _, err := io.ReadFull(rand.Reader, scalar[:]); err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(scalar[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	inner.Write(pub)

	// 中层:握手消息头(02 + uint24 长度)
	var mid bytes.Buffer
	mid.WriteByte(handshakeTypeSrvHello)
	var l3 [4]byte
	binary.BigEndian.PutUint32(l3[:], uint32(inner.Len()))
	mid.Write(l3[1:]) // uint24
	mid.Write(inner.Bytes())

	// 外层:记录头 16 03 03 + uint16 长度
	var pkt bytes.Buffer
	pkt.WriteByte(recTypeHandshake)
	pkt.Write(tlsVersion[:])
	var l2 [2]byte
	binary.BigEndian.PutUint16(l2[:], uint16(mid.Len()))
	pkt.Write(l2[:])
	pkt.Write(mid.Bytes())

	// ChangeCipherSpec
	pkt.Write(changeCipherSpecRecord[:])

	// 恰好一条 noise ApplicationData(体积模仿真实 TLS1.3 握手后续)
	noiseLen := 2500 + mrand(2200)
	noise := make([]byte, noiseLen)
	if _, err := io.ReadFull(rand.Reader, noise); err != nil {
		return nil, err
	}
	var nh [recHeaderLen]byte
	nh[0] = recTypeApplicationData
	nh[1], nh[2] = tlsVersion[0], tlsVersion[1]
	binary.BigEndian.PutUint16(nh[3:5], uint16(noiseLen))
	pkt.Write(nh[:])
	pkt.Write(noise)

	// digest:HMAC(secret, clientRandom ‖ 整包),写回偏移 11
	out := pkt.Bytes()
	mac := hmac.New(sha256.New, secret)
	mac.Write(info.random[:])
	mac.Write(out)
	copy(out[tlsRandomOffset:tlsRandomOffset+tlsRandomLen], mac.Sum(nil))
	return out, nil
}

// mrand 返回 [0,n) 的随机数(用 crypto/rand,避免可预测的 noise 体积)。
func mrand(n int) int {
	var b [4]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return n / 2
	}
	return int(binary.LittleEndian.Uint32(b[:]) % uint32(n))
}
