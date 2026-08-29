package snellv6

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestSessionKeyGolden 验证 vendored 的 Snell v6 会话密钥 KDF(Argon2id t=3,m=8KiB,p=1)
// 在 NTR 构建下与 crypto.go 记录的 golden 向量逐字节一致 —— 确认密码学未在搬运中走样。
func TestSessionKeyGolden(t *testing.T) {
	psk := []byte("0123456789abcdef")
	var salt [16]byte
	for i := range salt {
		salt[i] = byte(i) // 00..0f
	}
	want, _ := hex.DecodeString("b1113799efdfa051f080dd1be8d4855bc8b141224c325ac55ba5140261d14f99")

	got, err := SessionKey(psk, salt[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("SessionKey mismatch\n got=%x\nwant=%x", got, want)
	}
}

// TestNonceCounterLE 验证 12 字节小端计数器进位(sub_1D55D0 case 12)。
func TestNonceCounterLE(t *testing.T) {
	var n Nonce
	// 把低 64 位设成 0xFFFFFFFFFFFFFFFF,Inc 应进位到高 32 位。
	binary.LittleEndian.PutUint64(n[0:8], ^uint64(0))
	n.Inc()
	if lo := binary.LittleEndian.Uint64(n[0:8]); lo != 0 {
		t.Fatalf("low word = %d, want 0 (wrapped)", lo)
	}
	if hi := binary.LittleEndian.Uint32(n[8:12]); hi != 1 {
		t.Fatalf("high word = %d, want 1 (carried)", hi)
	}
}

// TestParseCommandConnect 验证 stage-S0 请求头解析(version=1, CONNECT, clientID, host:port)。
func TestParseCommandConnect(t *testing.T) {
	// [1][cmdConnect][idLen=3]abc[hostLen=11]example.com[port BE 0x01BB=443]
	var b bytes.Buffer
	b.WriteByte(1)          // version
	b.WriteByte(cmdConnect) // command
	b.WriteByte(3)          // idLen
	b.WriteString("abc")    // clientID
	b.WriteByte(11)         // hostLen
	b.WriteString("example.com")
	b.Write([]byte{0x01, 0xBB}) // port 443 BE

	cmd, n, err := parseCommand(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if cmd == nil {
		t.Fatal("parseCommand returned nil (need more bytes?)")
	}
	if cmd.command != cmdConnect || cmd.clientID != "abc" || cmd.host != "example.com" || cmd.port != 443 {
		t.Fatalf("decoded %+v", *cmd)
	}
	if n != b.Len() {
		t.Fatalf("consumed %d, want %d", n, b.Len())
	}
}
