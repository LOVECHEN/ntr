package service

import (
	"encoding/binary"
	"testing"

	"github.com/LOVECHEN/ntr/core/endpoint"
)

// mkSTUN 造一份最小合法 STUN 绑定请求(type=0x0001 Binding Request,magic cookie + 12B txid + attrLen 字节)。
func mkSTUN(attrLen int) []byte {
	b := make([]byte, 20+attrLen)
	binary.BigEndian.PutUint16(b[0:2], 0x0001)          // message type
	binary.BigEndian.PutUint16(b[2:4], uint16(attrLen)) // message length
	binary.BigEndian.PutUint32(b[4:8], 0x2112A442)      // magic cookie
	return b
}

func TestIsSTUN(t *testing.T) {
	if !isSTUN(mkSTUN(0)) {
		t.Fatal("最小合法 STUN 应识别")
	}
	if !isSTUN(mkSTUN(8)) {
		t.Fatal("带属性的 STUN 应识别")
	}
	// 反例:短包、错 cookie、长度字段超实际。
	if isSTUN(make([]byte, 19)) {
		t.Error("<20 字节不应判 STUN")
	}
	bad := mkSTUN(0)
	binary.BigEndian.PutUint32(bad[4:8], 0xdeadbeef)
	if isSTUN(bad) {
		t.Error("错 magic cookie 不应判 STUN")
	}
	lenLie := mkSTUN(0)
	binary.BigEndian.PutUint16(lenLie[2:4], 100) // 声称 100 字节属性但实际没有
	if isSTUN(lenLie) {
		t.Error("长度字段与实际不符不应判 STUN")
	}
	// 常见非 STUN 首字节(TLS ClientHello 0x16 / HTTP 'G')
	if isSTUN([]byte("GET / HTTP/1.1\r\n\r\n................")) {
		t.Error("HTTP 不应判 STUN")
	}
}

func TestSniffPacket(t *testing.T) {
	if p := sniffPacket(mkSTUN(0)); p != endpoint.SniffSTUN {
		t.Fatalf("STUN datagram 应嗅为 SniffSTUN,实为 %v", p)
	}
	if p := sniffPacket([]byte("not stun at all, just bytes......")); p != endpoint.SniffNone {
		t.Fatalf("非 STUN 应为 SniffNone,实为 %v", p)
	}
	if p := sniffPacket(mkQUIC(0x00000001)); p != endpoint.SniffQUIC {
		t.Fatalf("QUIC v1 Initial 应嗅为 SniffQUIC,实为 %v", p)
	}
	if endpoint.SniffSTUN.String() != "stun" {
		t.Fatal("SniffSTUN.String() 应为 stun")
	}
}

// mkQUIC 造一个长包头 QUIC 首包(byte0 长包头+fixed 位,version 4B)。
func mkQUIC(version uint32) []byte {
	b := make([]byte, 20)
	b[0] = 0xc0 // long header(0x80)+ fixed(0x40)
	b[1] = byte(version >> 24)
	b[2] = byte(version >> 16)
	b[3] = byte(version >> 8)
	b[4] = byte(version)
	return b
}

// TestIsQUIC:QUIC 长包头首包识别(不解密,仅凭 long-header 位 + 已知版本号)。
func TestIsQUIC(t *testing.T) {
	if !isQUIC(mkQUIC(0x00000001)) {
		t.Fatal("QUIC v1(0x00000001)应识别")
	}
	if !isQUIC(mkQUIC(0x6b3343cf)) {
		t.Fatal("QUIC v2(0x6b3343cf)应识别")
	}
	if !isQUIC(mkQUIC(0xff00001d)) {
		t.Fatal("draft-ietf-quic(0xff0000xx)应识别")
	}
	if isQUIC(mkQUIC(0x12345678)) {
		t.Error("未知版本不应判 QUIC")
	}
	short := mkQUIC(0x00000001)
	short[0] &^= 0x80 // 清长包头位 → 短包头(1-RTT),不作首包识别
	if isQUIC(short) {
		t.Error("短包头不应判 QUIC")
	}
	if isQUIC(make([]byte, 4)) {
		t.Error("不足 5 字节不应判 QUIC")
	}
}

// TestIsDTLS:DTLS record 识别(WebRTC 媒体面)。content-type=22 handshake + 版本 fe fd(DTLS1.2)/fe ff(1.0)。
func TestIsDTLS(t *testing.T) {
	mk := func(ct, vmaj, vmin byte) []byte {
		b := make([]byte, 13)
		b[0], b[1], b[2] = ct, vmaj, vmin
		return b
	}
	if !isDTLS(mk(22, 0xfe, 0xfd)) {
		t.Fatal("DTLS1.2 handshake 应识别")
	}
	if !isDTLS(mk(23, 0xfe, 0xff)) {
		t.Fatal("DTLS1.0 appdata 应识别")
	}
	if isDTLS(mk(99, 0xfe, 0xfd)) {
		t.Error("非法 content-type 不应判 DTLS")
	}
	if isDTLS(mk(22, 0x03, 0x03)) {
		t.Error("TLS(非 DTLS)版本不应判 DTLS")
	}
	if isDTLS(make([]byte, 12)) {
		t.Error("<13 字节不应判 DTLS")
	}
	if p := sniffPacket(mk(22, 0xfe, 0xfd)); p != endpoint.SniffDTLS || p.String() != "dtls" {
		t.Fatalf("DTLS datagram 应嗅为 SniffDTLS/dtls,实为 %v", p)
	}
}
