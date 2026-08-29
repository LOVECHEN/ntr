package connectip

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"

	"github.com/metacubex/quic-go/quicvarint"
)

// RFC 9484 §4.7 的三种 capsule。线格式:Type(i) Length(i) 后跟【可重复】的条目数组(填满 Length)。
//
//	0x01 ADDRESS_ASSIGN      条目 = Request ID(i) + IP Version(8) + IP Address(32/128) + Prefix Length(8)
//	0x02 ADDRESS_REQUEST     条目布局同上
//	0x03 ROUTE_ADVERTISEMENT 条目 = IP Version(8) + Start IP(32/128) + End IP(32/128) + IP Protocol(8)
//
// ★ 两个易错点:
//   - ROUTE_ADVERTISEMENT 的条目【没有 Request ID】,且用 Start/End 双地址而非前缀。
//   - 地址字段是【变宽】的:必须先读 IP Version(8) 才知道后面是 32 还是 128 bit,禁止定长解析。
const (
	capsuleAddressAssign      = 0x01
	capsuleAddressRequest     = 0x02
	capsuleRouteAdvertisement = 0x03
)

var (
	errShortCapsule  = errors.New("connect-ip: capsule 载荷截断")
	errBadIPVersion  = errors.New("connect-ip: IP Version 必须为 4 或 6")
	errBadPrefixLen  = errors.New("connect-ip: 前缀长度超出地址位宽")
	errRangeReversed = errors.New("connect-ip: 地址区间 End < Start")
)

// AssignedAddress 是 ADDRESS_ASSIGN / ADDRESS_REQUEST 的条目。
// 响应某个 request 时 RequestID 回填对应值;主动下发时为 0(§4.7.1)。
type AssignedAddress struct {
	RequestID uint64
	Prefix    netip.Prefix
}

// IPRoute 是 ROUTE_ADVERTISEMENT 的条目:一段可路由的地址区间。
// IPProtocol = 0 表示所有协议(§4.7.3)。
type IPRoute struct {
	Start      netip.Addr
	End        netip.Addr
	IPProtocol uint8
}

// ipVersionOf 返回地址的 IP 版本号与字节宽度。
func ipVersionOf(a netip.Addr) (ver uint8, width int, err error) {
	switch {
	case a.Is4():
		return 4, 4, nil
	case a.Is6():
		return 6, 16, nil
	}
	return 0, 0, errBadIPVersion
}

// readAddrOf 按 version 读定宽地址(4 → 32bit,6 → 128bit)。
func readAddrOf(r *bytes.Reader, ver uint8) (netip.Addr, error) {
	var width int
	switch ver {
	case 4:
		width = 4
	case 6:
		width = 16
	default:
		return netip.Addr{}, errBadIPVersion
	}
	b := make([]byte, width)
	if _, err := readFull(r, b); err != nil {
		return netip.Addr{}, err
	}
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, errBadIPVersion
	}
	return a, nil
}

func readFull(r *bytes.Reader, b []byte) (int, error) {
	n, err := r.Read(b)
	if err != nil || n != len(b) {
		return n, errShortCapsule
	}
	return n, nil
}

// EncodeAddressAssign 编码 ADDRESS_ASSIGN capsule(不含外层 capsule 头由调用方决定时也可复用)。
func EncodeAddressAssign(addrs []AssignedAddress) ([]byte, error) {
	return encodeAddressCapsule(capsuleAddressAssign, addrs)
}

// EncodeAddressRequest 编码 ADDRESS_REQUEST capsule。
func EncodeAddressRequest(addrs []AssignedAddress) ([]byte, error) {
	return encodeAddressCapsule(capsuleAddressRequest, addrs)
}

func encodeAddressCapsule(typ uint64, addrs []AssignedAddress) ([]byte, error) {
	var body []byte
	for _, a := range addrs {
		ver, width, err := ipVersionOf(a.Prefix.Addr())
		if err != nil {
			return nil, err
		}
		if a.Prefix.Bits() < 0 || a.Prefix.Bits() > width*8 {
			return nil, errBadPrefixLen
		}
		body = quicvarint.Append(body, a.RequestID)
		body = append(body, ver)
		ip := a.Prefix.Addr().AsSlice()
		body = append(body, ip...)
		body = append(body, uint8(a.Prefix.Bits()))
	}
	return wrapCapsule(typ, body), nil
}

// EncodeRouteAdvertisement 编码 ROUTE_ADVERTISEMENT capsule。
func EncodeRouteAdvertisement(routes []IPRoute) ([]byte, error) {
	var body []byte
	for _, r := range routes {
		ver, _, err := ipVersionOf(r.Start)
		if err != nil {
			return nil, err
		}
		evVer, _, err := ipVersionOf(r.End)
		if err != nil {
			return nil, err
		}
		if ver != evVer {
			return nil, errBadIPVersion
		}
		if r.End.Less(r.Start) {
			return nil, errRangeReversed
		}
		body = append(body, ver)
		body = append(body, r.Start.AsSlice()...)
		body = append(body, r.End.AsSlice()...)
		body = append(body, r.IPProtocol)
	}
	return wrapCapsule(capsuleRouteAdvertisement, body), nil
}

// wrapCapsule 加上 Type(i) + Length(i) 头。
func wrapCapsule(typ uint64, body []byte) []byte {
	out := quicvarint.Append(nil, typ)
	out = quicvarint.Append(out, uint64(len(body)))
	return append(out, body...)
}

// ParseCapsule 解析一条 capsule,返回类型与已解出的条目。
// 未知类型返回 (typ, nil, nil, nil) —— 按 RFC 应静默忽略而非断连。
func ParseCapsule(typ uint64, body []byte) ([]AssignedAddress, []IPRoute, error) {
	r := bytes.NewReader(body)
	switch typ {
	case capsuleAddressAssign, capsuleAddressRequest:
		var out []AssignedAddress
		for r.Len() > 0 {
			reqID, err := quicvarint.Read(r)
			if err != nil {
				return nil, nil, errShortCapsule
			}
			verB, err := r.ReadByte()
			if err != nil {
				return nil, nil, errShortCapsule
			}
			a, err := readAddrOf(r, verB)
			if err != nil {
				return nil, nil, err
			}
			plen, err := r.ReadByte()
			if err != nil {
				return nil, nil, errShortCapsule
			}
			if int(plen) > a.BitLen() {
				return nil, nil, errBadPrefixLen
			}
			out = append(out, AssignedAddress{RequestID: reqID, Prefix: netip.PrefixFrom(a, int(plen))})
		}
		return out, nil, nil
	case capsuleRouteAdvertisement:
		var out []IPRoute
		for r.Len() > 0 {
			verB, err := r.ReadByte()
			if err != nil {
				return nil, nil, errShortCapsule
			}
			start, err := readAddrOf(r, verB)
			if err != nil {
				return nil, nil, err
			}
			end, err := readAddrOf(r, verB)
			if err != nil {
				return nil, nil, err
			}
			proto, err := r.ReadByte()
			if err != nil {
				return nil, nil, errShortCapsule
			}
			if end.Less(start) {
				return nil, nil, errRangeReversed
			}
			out = append(out, IPRoute{Start: start, End: end, IPProtocol: proto})
		}
		return nil, out, nil
	default:
		return nil, nil, nil // 未知 capsule:忽略
	}
}

// ReadCapsule 从字节流里读一条 capsule(Type + Length + body),返回类型、体与消耗字节数。
func ReadCapsule(b []byte) (typ uint64, body []byte, n int, err error) {
	r := bytes.NewReader(b)
	typ, err = quicvarint.Read(r)
	if err != nil {
		return 0, nil, 0, errShortCapsule
	}
	length, err := quicvarint.Read(r)
	if err != nil {
		return 0, nil, 0, errShortCapsule
	}
	consumed := len(b) - r.Len()
	if uint64(len(b)-consumed) < length {
		return 0, nil, 0, errShortCapsule
	}
	if length > uint64(^uint32(0)) {
		return 0, nil, 0, fmt.Errorf("connect-ip: capsule 长度 %d 过大", length)
	}
	return typ, b[consumed : consumed+int(length)], consumed + int(length), nil
}
