package connectip

import (
	"bytes"
	"net/netip"
	"testing"
)

// TestAddressAssignRoundTrip:ADDRESS_ASSIGN 编解码往返(IPv4/IPv6 混合,变宽地址)。
func TestAddressAssignRoundTrip(t *testing.T) {
	in := []AssignedAddress{
		{RequestID: 0, Prefix: netip.MustParsePrefix("10.7.0.2/32")},
		{RequestID: 7, Prefix: netip.MustParsePrefix("2001:db8::42/128")},
		{RequestID: 1, Prefix: netip.MustParsePrefix("192.0.2.0/24")},
	}
	raw, err := EncodeAddressAssign(in)
	if err != nil {
		t.Fatal(err)
	}
	typ, body, n, err := ReadCapsule(raw)
	if err != nil {
		t.Fatal(err)
	}
	if typ != capsuleAddressAssign {
		t.Fatalf("类型应为 0x01,得到 %#x", typ)
	}
	if n != len(raw) {
		t.Fatalf("消耗字节 %d != 总长 %d", n, len(raw))
	}
	got, routes, err := ParseCapsule(typ, body)
	if err != nil {
		t.Fatal(err)
	}
	if routes != nil {
		t.Fatal("ADDRESS_ASSIGN 不应解出 routes")
	}
	if len(got) != len(in) {
		t.Fatalf("条目数 %d != %d", len(got), len(in))
	}
	for i := range in {
		if got[i].RequestID != in[i].RequestID || got[i].Prefix != in[i].Prefix {
			t.Errorf("条目 %d 不符:%+v != %+v", i, got[i], in[i])
		}
	}
}

// TestAddressRequestType:ADDRESS_REQUEST 用 0x02,布局与 ASSIGN 相同。
func TestAddressRequestType(t *testing.T) {
	raw, err := EncodeAddressRequest([]AssignedAddress{
		{RequestID: 3, Prefix: netip.MustParsePrefix("0.0.0.0/0")}, // 无偏好
	})
	if err != nil {
		t.Fatal(err)
	}
	typ, body, _, err := ReadCapsule(raw)
	if err != nil {
		t.Fatal(err)
	}
	if typ != capsuleAddressRequest {
		t.Fatalf("类型应为 0x02,得到 %#x", typ)
	}
	got, _, err := ParseCapsule(typ, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RequestID != 3 {
		t.Fatalf("解析错:%+v", got)
	}
}

// TestRouteAdvertisementRoundTrip:ROUTE_ADVERTISEMENT 布局与另两个【不同】——
// 无 Request ID,用 Start/End 双地址 + IP Protocol。
func TestRouteAdvertisementRoundTrip(t *testing.T) {
	in := []IPRoute{
		{Start: netip.MustParseAddr("0.0.0.0"), End: netip.MustParseAddr("255.255.255.255"), IPProtocol: 0},
		{Start: netip.MustParseAddr("2001:db8::"), End: netip.MustParseAddr("2001:db8::ffff"), IPProtocol: 6},
	}
	raw, err := EncodeRouteAdvertisement(in)
	if err != nil {
		t.Fatal(err)
	}
	typ, body, _, err := ReadCapsule(raw)
	if err != nil {
		t.Fatal(err)
	}
	if typ != capsuleRouteAdvertisement {
		t.Fatalf("类型应为 0x03,得到 %#x", typ)
	}
	addrs, got, err := ParseCapsule(typ, body)
	if err != nil {
		t.Fatal(err)
	}
	if addrs != nil {
		t.Fatal("ROUTE_ADVERTISEMENT 不应解出 addrs")
	}
	if len(got) != len(in) {
		t.Fatalf("条目数 %d != %d", len(got), len(in))
	}
	for i := range in {
		if got[i].Start != in[i].Start || got[i].End != in[i].End || got[i].IPProtocol != in[i].IPProtocol {
			t.Errorf("条目 %d 不符:%+v != %+v", i, got[i], in[i])
		}
	}
}

// TestVariableWidthAddress:同一条 capsule 里 v4/v6 混排,解析必须按 Version 变宽。
func TestVariableWidthAddress(t *testing.T) {
	raw, err := EncodeAddressAssign([]AssignedAddress{
		{RequestID: 1, Prefix: netip.MustParsePrefix("1.2.3.4/32")}, // 32 bit
		{RequestID: 2, Prefix: netip.MustParsePrefix("::1/128")},    // 128 bit
		{RequestID: 3, Prefix: netip.MustParsePrefix("5.6.7.8/32")}, // 32 bit
	})
	if err != nil {
		t.Fatal(err)
	}
	typ, body, _, _ := ReadCapsule(raw)
	got, _, err := ParseCapsule(typ, body)
	if err != nil {
		t.Fatalf("变宽解析失败:%v", err)
	}
	if len(got) != 3 {
		t.Fatalf("应解出 3 条,得到 %d", len(got))
	}
	if !got[0].Prefix.Addr().Is4() || !got[1].Prefix.Addr().Is6() || !got[2].Prefix.Addr().Is4() {
		t.Fatalf("变宽顺序错:%v %v %v", got[0].Prefix, got[1].Prefix, got[2].Prefix)
	}
}

// TestUnknownCapsuleIgnored:未知 capsule 类型按 RFC 应静默忽略,不报错。
func TestUnknownCapsuleIgnored(t *testing.T) {
	addrs, routes, err := ParseCapsule(0x99, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("未知 capsule 不应报错:%v", err)
	}
	if addrs != nil || routes != nil {
		t.Fatal("未知 capsule 不应解出内容")
	}
}

// TestTruncatedCapsule:截断的 capsule 必须报错而非 panic。
func TestTruncatedCapsule(t *testing.T) {
	raw, _ := EncodeAddressAssign([]AssignedAddress{
		{RequestID: 1, Prefix: netip.MustParsePrefix("2001:db8::1/128")},
	})
	for cut := 1; cut < len(raw); cut++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("截断到 %d 字节时 panic:%v", cut, r)
				}
			}()
			typ, body, _, err := ReadCapsule(raw[:cut])
			if err != nil {
				return // 头就截断了,预期
			}
			_, _, _ = ParseCapsule(typ, body) // 体截断应返回 error,不 panic
		}()
	}
}

// TestBadIPVersion:非 4/6 的 Version 必须被拒。
func TestBadIPVersion(t *testing.T) {
	// 手工构造:RequestID=0, Version=9(非法)
	body := []byte{0x00, 0x09, 1, 2, 3, 4, 32}
	if _, _, err := ParseCapsule(capsuleAddressAssign, body); err == nil {
		t.Fatal("非法 IP Version 应被拒")
	}
}

// TestRouteReversedRejected:End < Start 必须被拒。
func TestRouteReversedRejected(t *testing.T) {
	_, err := EncodeRouteAdvertisement([]IPRoute{
		{Start: netip.MustParseAddr("10.0.0.9"), End: netip.MustParseAddr("10.0.0.1")},
	})
	if err == nil {
		t.Fatal("End < Start 应被拒")
	}
}

// TestMultipleCapsulesInStream:连续多条 capsule 能按 n 逐条推进解析。
func TestMultipleCapsulesInStream(t *testing.T) {
	a, _ := EncodeAddressAssign([]AssignedAddress{{Prefix: netip.MustParsePrefix("10.0.0.1/32")}})
	r, _ := EncodeRouteAdvertisement([]IPRoute{{Start: netip.MustParseAddr("0.0.0.0"), End: netip.MustParseAddr("255.255.255.255")}})
	stream := append(append([]byte{}, a...), r...)

	var types []uint64
	for len(stream) > 0 {
		typ, _, n, err := ReadCapsule(stream)
		if err != nil {
			t.Fatal(err)
		}
		types = append(types, typ)
		stream = stream[n:]
	}
	if len(types) != 2 || types[0] != capsuleAddressAssign || types[1] != capsuleRouteAdvertisement {
		t.Fatalf("流式解析错:%v", types)
	}
}

// TestContextIDZeroPrefix:datagram 载荷前缀 —— connect-ip 的 Context ID 0 后跟【完整 IP 包】
// (与 connect-udp 只放 UDP payload 不同),此处验证编解码对称。
func TestContextIDZeroPrefix(t *testing.T) {
	ipPkt := []byte{0x45, 0x00, 0x00, 0x14} // 一个 IPv4 头起始
	wire := prependContextID(ipPkt)
	if wire[0] != 0x00 {
		t.Fatalf("Context ID 0 应编成单字节 0x00,得到 %#x", wire[0])
	}
	got, ok := stripContextID(wire)
	if !ok || !bytes.Equal(got, ipPkt) {
		t.Fatalf("往返失败:ok=%v got=%x", ok, got)
	}
	if _, ok := stripContextID([]byte{0x01, 0xAA}); ok {
		t.Error("非零 Context ID 应被丢弃")
	}
}
