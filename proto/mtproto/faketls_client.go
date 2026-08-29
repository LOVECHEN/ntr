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
)

// 客户端侧 faketls:构造带 digest 的 ClientHello、读并校验服务端三段响应。
//
// digest 构造与服务端校验互为逆运算:
//   random = HMAC-SHA256(secret, 整帧但 random 位置填 0) XOR (28 字节 0 ‖ LE32(now))
// 服务端算同样的 HMAC 再 XOR 回来,前 28 字节归零即认证通过,后 4 字节即时间戳。

// 客户端 ClientHello 里通告的 cipher suites(含 GREASE 占位,服务端会跳过 GREASE 取首个真套件)。
var clientCipherSuites = []uint16{
	0x1a1a, // GREASE
	0x1301, // TLS_AES_128_GCM_SHA256
	0x1302, // TLS_AES_256_GCM_SHA384
	0x1303, // TLS_CHACHA20_POLY1305_SHA256
	0xc02b, 0xc02f, 0xc02c, 0xc030,
	0xcca9, 0xcca8, 0xc013, 0xc014,
	0x009c, 0x009d, 0x002f, 0x0035,
}

var errBadServerHello = errors.New("mtproto/faketls: 服务端响应 digest 校验失败")

// buildClientHello 造一条带 digest 的 ClientHello 记录(SNI = host)。
func buildClientHello(secret []byte, host string) ([]byte, [tlsRandomLen]byte, error) {
	var zero [tlsRandomLen]byte

	var sessionID [32]byte
	if _, err := io.ReadFull(rand.Reader, sessionID[:]); err != nil {
		return nil, zero, err
	}

	// ---- 握手体 ----
	var body bytes.Buffer
	body.Write(tlsVersion[:])              // client_version 03 03
	body.Write(make([]byte, tlsRandomLen)) // random 占位(先全 0)
	body.WriteByte(byte(len(sessionID)))   // session_id 长度
	body.Write(sessionID[:])               //
	var csBuf bytes.Buffer                 // cipher_suites
	for _, cs := range clientCipherSuites {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], cs)
		csBuf.Write(b[:])
	}
	var csLen [2]byte
	binary.BigEndian.PutUint16(csLen[:], uint16(csBuf.Len()))
	body.Write(csLen[:])
	body.Write(csBuf.Bytes())
	body.WriteByte(0x01) // compression_methods 长度
	body.WriteByte(0x00) // null 压缩

	// ---- extensions:SNI ----
	var sni bytes.Buffer
	sni.WriteByte(0x00) // name_type = host_name
	var hl [2]byte
	binary.BigEndian.PutUint16(hl[:], uint16(len(host)))
	sni.Write(hl[:])
	sni.WriteString(host)
	var sniList [2]byte
	binary.BigEndian.PutUint16(sniList[:], uint16(sni.Len()))

	var exts bytes.Buffer
	exts.Write([]byte{0x00, 0x00}) // ext type = server_name
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(2+sni.Len()))
	exts.Write(extLen[:])
	exts.Write(sniList[:])
	exts.Write(sni.Bytes())
	// supported_versions(TLS 1.3),让外形更像真实 ClientHello
	exts.Write([]byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04})

	var extsLen [2]byte
	binary.BigEndian.PutUint16(extsLen[:], uint16(exts.Len()))
	body.Write(extsLen[:])
	body.Write(exts.Bytes())

	// ---- 握手消息头 + 记录头 ----
	var hs bytes.Buffer
	hs.WriteByte(handshakeTypeHello)
	var l3 [4]byte
	binary.BigEndian.PutUint32(l3[:], uint32(body.Len()))
	hs.Write(l3[1:]) // uint24
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(recTypeHandshake)
	rec.Write([]byte{0x03, 0x01}) // ClientHello 记录层版本惯用 03 01
	var l2 [2]byte
	binary.BigEndian.PutUint16(l2[:], uint16(hs.Len()))
	rec.Write(l2[:])
	rec.Write(hs.Bytes())

	out := rec.Bytes()

	// ---- digest:HMAC(整帧,random 位置为 0)XOR (28 字节 0 ‖ LE32(now)) ----
	mac := hmac.New(sha256.New, secret)
	mac.Write(out[:tlsRandomOffset])
	mac.Write(make([]byte, tlsRandomLen))
	mac.Write(out[tlsRandomOffset+tlsRandomLen:])
	digest := mac.Sum(nil)

	var tsBuf [4]byte
	binary.LittleEndian.PutUint32(tsBuf[:], uint32(time.Now().Unix()))
	for i := range 4 {
		digest[tlsRandomLen-4+i] ^= tsBuf[i]
	}
	copy(out[tlsRandomOffset:tlsRandomOffset+tlsRandomLen], digest)

	var clientRandom [tlsRandomLen]byte
	copy(clientRandom[:], digest)
	return out, clientRandom, nil
}

// readServerHello 读服务端三段响应(ServerHello + CCS + 一条 ApplicationData noise)并校验 digest:
// 把 server random 位置清零后,HMAC(secret, clientRandom ‖ 整包) 应等于收到的 server random。
func readServerHello(br *bufio.Reader, secret []byte, clientRandom [tlsRandomLen]byte) error {
	var whole bytes.Buffer
	for range 3 { // 恰好三条记录
		var hdr [recHeaderLen]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint16(hdr[3:5]))
		if n > maxRecordPayload {
			return errRecordTooBig
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(br, payload); err != nil {
			return err
		}
		whole.Write(hdr[:])
		whole.Write(payload)
	}
	pkt := whole.Bytes()
	if len(pkt) < tlsRandomOffset+tlsRandomLen {
		return errBadRecord
	}
	var got [tlsRandomLen]byte
	copy(got[:], pkt[tlsRandomOffset:tlsRandomOffset+tlsRandomLen])
	// 清零后重算
	copy(pkt[tlsRandomOffset:tlsRandomOffset+tlsRandomLen], make([]byte, tlsRandomLen))
	mac := hmac.New(sha256.New, secret)
	mac.Write(clientRandom[:])
	mac.Write(pkt)
	if subtle.ConstantTimeCompare(got[:], mac.Sum(nil)) != 1 {
		return errBadServerHello
	}
	return nil
}
