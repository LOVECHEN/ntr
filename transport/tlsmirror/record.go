// Package tlsmirror 自写实现 tlsmirror 传输 —— 把隧道隐写进一条【真·TLS 会话】里(v2fly v2ray-core v5
// 起源,mihomo 移植;主线 Xray/XTLS 与 sing-box 均无)。是"镜像/诱骗路由"式抗检测:客户端与一台【真实
// HTTPS 后端】做端到端真 TLS 握手,tlsmirror 服务端只当透明中继把两腿记录互相镜像转发,同时把隧道数据
// 用 AEAD 封成【额外插入的 application_data 记录】混进流里 —— 对旁观者这就是一条访问 microsoft.com 之类
// 的普通 TLS 连接。是 BaseTransport(自产隐蔽 link.Stream),惯用叠法 [tlsmirror, vmess]。
//
// 线格式(禁改,逐字节承 mihomo/v2ray transport/tlsmirror):
//   - TLS 记录 = [1B 类型][2B 版本][2B BE 长度][fragment](见 record.go,标准 TLS record layer)。
//   - 隐蔽记录 = recordType=0x17(application_data)的记录,其 fragment = AES-128-GCM_Seal(隐蔽密钥,
//     nonce=隐式 8B 小端计数器, 明文, aad=nil);8B nonce 【不上线】,两端锁步计数(见 crypto.go)。
//   - 识别靠【试解密】:收到 app-data 记录先用隐蔽 decryptor.Open 试解 —— 成功=隐蔽记录(丢弃+取出载荷),
//     失败=真 TLS 记录(照转后端)。真 TLS 记录几乎不可能在隐蔽密钥下解开(误判率 ~2^-128)。
//   - 隐蔽密钥 = HKDF-SHA256(primaryKey||clientRandom||serverRandom, 标签)。clientRandom/serverRandom
//     从明文 ClientHello/ServerHello 抓(TLS1.3 里两个 Hello 仍明文)。方向标签 :c2s / :s2c。
//
// v1:仅 TLS1.3 载体(explicitNonceOverhead=0),不含 padding/水印/enrollment/流量生成器/uTLS 指纹
// (均为可选抗检测层,不改隐蔽 app-data 的线格式,mihomo "default" 用例正是此最小集)。
package tlsmirror

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

const (
	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeHandshake        = 22
	recordTypeApplicationData  = 23

	maxTLSRecordPayload = 16384
)

// record 是一条 TLS 记录。inserted 标记为本地插入的隐蔽记录(发送侧走 recordWriter 的插入队列)。
type record struct {
	recordType byte
	version    [2]byte
	fragment   []byte
	inserted   bool
}

// readRecord 从流读一条完整 TLS 记录 + 其原始字节(转发用)。
func readRecord(reader *bufio.Reader) (*record, []byte, error) {
	header := make([]byte, 5)
	n, err := io.ReadFull(reader, header)
	if err != nil {
		return nil, header[:n], err
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length > maxTLSRecordPayload {
		return nil, header, errors.New("tlsmirror: tls record is too large")
	}
	fragment := make([]byte, length)
	n, err = io.ReadFull(reader, fragment)
	raw := append(append([]byte(nil), header...), fragment[:n]...)
	if err != nil {
		return nil, raw, err
	}
	return &record{
		recordType: header[0],
		version:    [2]byte{header[1], header[2]},
		fragment:   fragment,
	}, raw, nil
}

// writeRecord 写一条 TLS 记录并 flush。
func writeRecord(writer *bufio.Writer, rec *record) error {
	if len(rec.fragment) > maxTLSRecordPayload {
		return errors.New("tlsmirror: tls record is too large")
	}
	var header [5]byte
	header[0] = rec.recordType
	header[1] = rec.version[0]
	header[2] = rec.version[1]
	binary.BigEndian.PutUint16(header[3:5], uint16(len(rec.fragment)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	if _, err := writer.Write(rec.fragment); err != nil {
		return err
	}
	return writer.Flush()
}

// duplicateRecord 深拷贝一条记录(插入队列跨 goroutine,避免 fragment 别名)。
func duplicateRecord(rec *record) *record {
	dup := *rec
	dup.fragment = append([]byte(nil), rec.fragment...)
	return &dup
}

// parseClientRandom 从 ClientHello 的 handshake fragment 抓 32B client random(偏移 6:38)。
func parseClientRandom(fragment []byte) ([32]byte, error) {
	var random [32]byte
	if len(fragment) < 38 || fragment[0] != 1 {
		return random, errors.New("tlsmirror: invalid client hello")
	}
	copy(random[:], fragment[6:38])
	return random, nil
}

// hasZeroExplicitNonce 判断记录前 8B(TLS1.2 GCM 显式 nonce 位)是否全 0(用于校验 CCS 后首条加密记录)。
func hasZeroExplicitNonce(fragment []byte) bool {
	if len(fragment) < 8 {
		return false
	}
	for _, b := range fragment[:8] {
		if b != 0 {
			return false
		}
	}
	return true
}

// parseServerHello 从 ServerHello 抓 32B server random + 选中的 cipher suite。
func parseServerHello(fragment []byte) ([32]byte, uint16, error) {
	var random [32]byte
	if len(fragment) < 41 || fragment[0] != 2 {
		return random, 0, errors.New("tlsmirror: invalid server hello")
	}
	copy(random[:], fragment[6:38])
	sessionIDLen := int(fragment[38])
	cipherSuiteOffset := 39 + sessionIDLen
	if len(fragment) < cipherSuiteOffset+2 {
		return random, 0, errors.New("tlsmirror: invalid server hello session id")
	}
	return random, binary.BigEndian.Uint16(fragment[cipherSuiteOffset : cipherSuiteOffset+2]), nil
}

// peekFirstHandshakeRecord 从半缓冲里试解第一条握手记录(判断是否真 TLS 起手)。
// 返回 (记录, 还需更多字节数, 已消费字节数, err)。processed==0 且 needMore>0 表示需继续读。
func peekFirstHandshakeRecord(buffer []byte) (*record, int, int, error) {
	if len(buffer) < 5 {
		return nil, 5, 0, nil
	}
	if buffer[0] != recordTypeHandshake {
		return nil, 0, 0, errors.New("tlsmirror: unexpected first tls record type")
	}
	switch buffer[1] {
	case 0x01, 0x02:
	case 0x03:
		if buffer[2] > 0x03 {
			return nil, 0, 0, errors.New("tlsmirror: unexpected first tls record version")
		}
	default:
		return nil, 0, 0, errors.New("tlsmirror: unexpected first tls record version")
	}
	length := int(buffer[3])<<8 | int(buffer[4])
	if length > maxTLSRecordPayload {
		return nil, 0, 0, errors.New("tlsmirror: tls record is too large")
	}
	processed := 5 + length
	if len(buffer) < processed {
		return nil, processed, 0, nil
	}
	return &record{
		recordType: buffer[0],
		version:    [2]byte{buffer[1], buffer[2]},
		fragment:   append([]byte(nil), buffer[5:processed]...),
	}, 0, processed, nil
}
