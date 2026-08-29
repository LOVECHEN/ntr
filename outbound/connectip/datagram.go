package connectip

import (
	"bytes"

	"github.com/metacubex/quic-go/quicvarint"
)

// RFC 9484 §6:IP Proxying HTTP Datagram Payload = Context ID(i) + Payload。
// Context ID 0 时 Payload 是【完整 IP 包】(含 IP 头)——
// 这是与 RFC 9298 connect-udp 的关键分野:后者放的是 UDP 净荷(无 IP/UDP 头)。
// 非零 Context ID 未协商则必须丢弃。

// prependContextID 在完整 IP 包前拼 Context ID 0。
func prependContextID(ipPacket []byte) []byte {
	out := make([]byte, 0, 1+len(ipPacket))
	out = quicvarint.Append(out, 0)
	return append(out, ipPacket...)
}

// stripContextID 剥掉 Context ID,仅接受 0(其余按 RFC 丢弃)。
func stripContextID(data []byte) ([]byte, bool) {
	r := bytes.NewReader(data)
	id, err := quicvarint.Read(r)
	if err != nil || id != 0 {
		return nil, false
	}
	return data[len(data)-r.Len():], true
}
