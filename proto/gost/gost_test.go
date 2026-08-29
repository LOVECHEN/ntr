package gost

import (
	"bytes"
	"io"
	"net/netip"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
)

// readRequestForTest 模拟服务端读一条完整 relay 请求(header+payload)并解特征。
func readRequestForTest(t *testing.T, r io.Reader) (addr.Socksaddr, uint16, string, string) {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("读 header: %v", err)
	}
	if hdr[0] != version1 || hdr[1] != cmdConnect {
		t.Fatalf("header 不对: %x", hdr)
	}
	plen := int(hdr[2])<<8 | int(hdr[3])
	payload := make([]byte, plen)
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("读 payload: %v", err)
	}
	dst, network, user, pass, err := parseFeatures(payload)
	if err != nil {
		t.Fatalf("parseFeatures: %v", err)
	}
	return dst, network, user, pass
}

// TestGostWireRoundTrip:writeRelayRequest → 服务端解析,验证目标/网络/鉴权逐字节还原(IPv4/IPv6/域名 + 有无 auth)。
func TestGostWireRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		dst        addr.Socksaddr
		user, pass string
	}{
		{"ipv4", addr.Socksaddr{Addr: netip.AddrFrom4([4]byte{1, 2, 3, 4}), Port: 443}, "", ""},
		{"ipv6", addr.Socksaddr{Addr: netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 4: 0x12, 15: 0x01}), Port: 8080}, "", ""},
		{"domain", addr.Socksaddr{Fqdn: "example.com", Port: 80}, "", ""},
		{"domain+auth", addr.Socksaddr{Fqdn: "target.internal", Port: 22}, "alice", "s3cr3t"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeRelayRequest(&b, cmdConnect, tc.dst, networkTCP, tc.user, tc.pass)
			dst, network, user, pass := readRequestForTest(t, &b)
			if network != networkTCP {
				t.Fatalf("network=%d 期望 TCP", network)
			}
			if user != tc.user || pass != tc.pass {
				t.Fatalf("auth 还原错: %q/%q 期望 %q/%q", user, pass, tc.user, tc.pass)
			}
			if dst.String() != tc.dst.String() {
				t.Fatalf("dst 还原错: %s 期望 %s", dst.String(), tc.dst.String())
			}
		})
	}
}

// TestGostResponse:OK 响应可读过,非 OK 报错。
func TestGostResponse(t *testing.T) {
	var ok bytes.Buffer
	_ = writeResponse(&ok, statusOK)
	if err := readConnectResponse(&ok); err != nil {
		t.Fatalf("OK 响应应可读: %v", err)
	}
	var bad bytes.Buffer
	_ = writeResponse(&bad, statusUnauthorized)
	if err := readConnectResponse(&bad); err == nil {
		t.Fatal("非 OK 响应应报错")
	}
	// 带 features 的 OK 响应也应被跳过
	var withFeat bytes.Buffer
	withFeat.Write([]byte{version1, statusOK, 0x00, 0x03, 0xaa, 0xbb, 0xcc})
	withFeat.WriteString("payload-after")
	if err := readConnectResponse(&withFeat); err != nil {
		t.Fatalf("带 feature 的 OK 响应应可读: %v", err)
	}
	rest, _ := io.ReadAll(&withFeat)
	if string(rest) != "payload-after" {
		t.Fatalf("剥响应后残留错: %q", rest)
	}
}
