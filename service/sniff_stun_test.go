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
	if endpoint.SniffSTUN.String() != "stun" {
		t.Fatal("SniffSTUN.String() 应为 stun")
	}
}
