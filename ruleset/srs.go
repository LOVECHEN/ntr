package ruleset

// sing-box .srs 二进制规则集。字节级兼容 sing-box:
//   外层 "SRS"(3B) + version(1B) + zlib{ uvarint 规则数 + 规则* }
//   规则:uint8 类型(0=default,1=logical);default = 一串 item(uint8 itemType + 载荷),0xFF=final+invert。
//   我们只取分流所需维度:domain(succinct matcher)、domain_keyword、domain_regex、ip_cidr(+source),
//   其余 item 按格式跳过对齐;logical 递归摊平(geo 类 .srs 多为扁平 default,足够)。
//   源:SagerNet/sing-box common/srs/{binary,ip_set}.go、SagerNet/sing common/domain/{set,matcher}.go。

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"regexp"
	"sort"
	"unicode/utf8"

	"github.com/LOVECHEN/ntr/rule"
)

const (
	prefixLabel = '\r' // sing:域名后缀 .x 的标记
	rootLabel   = '\n' // sing:后缀 x(含 apex)的标记
)

// srsItem 编号(与 sing-box 一致)。
const (
	sItemQueryType uint8 = iota
	sItemNetwork
	sItemDomain
	sItemDomainKeyword
	sItemDomainRegex
	sItemSourceIPCIDR
	sItemIPCIDR
	sItemSourcePort
	sItemSourcePortRange
	sItemPort
	sItemPortRange
	sItemProcessName
	sItemProcessPath
	sItemPackageName
	sItemWIFISSID
	sItemWIFIBSSID
	sItemAdGuardDomain
	sItemProcessPathRegex
	sItemNetworkType
	sItemNetworkIsExpensive
	sItemNetworkIsConstrained
	sItemNetworkInterfaceAddress
	sItemDefaultInterfaceAddress
	sItemPackageNameRegex
	sItemFinal uint8 = 0xFF
)

// srsAcc 汇集一个 .srs 里所有规则的分流谓词。
type srsAcc struct {
	domains  []rule.DomainSet
	keywords []string
	regexes  []*regexp.Regexp
	ips      []*ipAddrRangeSet
}

// ParseSRSDomain 解 .srs 的域名维度 → rule.DomainSet(domain/后缀/keyword/regex 的并集)。
func ParseSRSDomain(data []byte) (rule.DomainSet, error) {
	acc, err := parseSRS(data)
	if err != nil {
		return nil, err
	}
	var u domainUnion
	u = append(u, acc.domains...)
	if len(acc.keywords) > 0 {
		u = append(u, keywordSet(acc.keywords))
	}
	if len(acc.regexes) > 0 {
		u = append(u, regexSet(acc.regexes))
	}
	if len(u) == 0 {
		return nil, fmt.Errorf("srs: 无域名维度规则")
	}
	return u, nil
}

// ParseSRSIP 解 .srs 的 IP 维度 → rule.IPSet(所有 ip_cidr 的并集)。
func ParseSRSIP(data []byte) (rule.IPSet, error) {
	acc, err := parseSRS(data)
	if err != nil {
		return nil, err
	}
	if len(acc.ips) == 0 {
		return nil, fmt.Errorf("srs: 无 ip_cidr 规则")
	}
	u := make(ipUnion, len(acc.ips))
	for i, s := range acc.ips {
		u[i] = s
	}
	return u, nil
}

func parseSRS(data []byte) (*srsAcc, error) {
	if len(data) < 4 || data[0] != 'S' || data[1] != 'R' || data[2] != 'S' {
		return nil, fmt.Errorf("srs: magic 非法")
	}
	// data[3]=version;剩余为 zlib
	zr, err := zlib.NewReader(bytes.NewReader(data[4:]))
	if err != nil {
		return nil, fmt.Errorf("srs: zlib:%w", err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("srs: 解压:%w", err)
	}
	r := bufio.NewReader(bytes.NewReader(raw))
	count, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	acc := &srsAcc{}
	for i := uint64(0); i < count; i++ {
		if err := readSRSRule(r, acc, 0); err != nil {
			return nil, fmt.Errorf("srs: 规则[%d]:%w", i, err)
		}
	}
	return acc, nil
}

func readSRSRule(r *bufio.Reader, acc *srsAcc, depth int) error {
	if depth > 100 {
		return fmt.Errorf("srs: logical 嵌套过深")
	}
	ruleType, err := r.ReadByte()
	if err != nil {
		return err
	}
	switch ruleType {
	case 0:
		return readSRSDefault(r, acc)
	case 1:
		return readSRSLogical(r, acc, depth)
	default:
		return fmt.Errorf("srs: 未知规则类型 %d", ruleType)
	}
}

func readSRSLogical(r *bufio.Reader, acc *srsAcc, depth int) error {
	if _, err := r.ReadByte(); err != nil { // mode(and/or)
		return err
	}
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	for i := uint64(0); i < n; i++ {
		if err := readSRSRule(r, acc, depth+1); err != nil {
			return err
		}
	}
	_, err = r.ReadByte() // invert bool
	return err
}

func readSRSDefault(r *bufio.Reader, acc *srsAcc) error {
	for {
		itemType, err := r.ReadByte()
		if err != nil {
			return err
		}
		switch itemType {
		case sItemDomain:
			ds, err := readSingSuccinct(r)
			if err != nil {
				return err
			}
			acc.domains = append(acc.domains, ds)
		case sItemDomainKeyword:
			ss, err := readItemStrings(r)
			if err != nil {
				return err
			}
			acc.keywords = append(acc.keywords, ss...)
		case sItemDomainRegex:
			ss, err := readItemStrings(r)
			if err != nil {
				return err
			}
			for _, expr := range ss {
				re, err := regexp.Compile(expr)
				if err == nil {
					acc.regexes = append(acc.regexes, re)
				}
			}
		case sItemIPCIDR, sItemSourceIPCIDR:
			set, err := readSRSIPSet(r)
			if err != nil {
				return err
			}
			if itemType == sItemIPCIDR {
				acc.ips = append(acc.ips, set)
			}
		case sItemQueryType, sItemSourcePort, sItemPort: // []uint16
			if err := skipUint16Slice(r); err != nil {
				return err
			}
		case sItemNetworkType: // []uint8
			if err := skipUint8Slice(r); err != nil {
				return err
			}
		case sItemNetwork, sItemSourcePortRange, sItemPortRange, sItemProcessName,
			sItemProcessPath, sItemProcessPathRegex, sItemPackageName, sItemPackageNameRegex,
			sItemWIFISSID, sItemWIFIBSSID: // ruleItemString
			if _, err := readItemStrings(r); err != nil {
				return err
			}
		case sItemNetworkIsExpensive, sItemNetworkIsConstrained: // 无载荷
		case sItemFinal:
			_, err := r.ReadByte() // invert bool
			return err
		default:
			return fmt.Errorf("srs: 不支持的 item 类型 %d(可能含 AdGuard/接口地址维度)", itemType)
		}
	}
}

// ── sing succinct 读取 + 匹配(\r/\n 特殊标签) ──

func readSingSuccinct(r *bufio.Reader) (rule.DomainSet, error) {
	if _, err := r.ReadByte(); err != nil { // flag 字节(sing 写 0)
		return nil, err
	}
	leaves, err := readUvarU64Slice(r)
	if err != nil {
		return nil, err
	}
	labelBitmap, err := readUvarU64Slice(r)
	if err != nil {
		return nil, err
	}
	labels, err := readUvarByteSlice(r)
	if err != nil {
		return nil, err
	}
	// 校验 + 补齐 leaves(对齐 sing readSuccinctSet)
	onesCount, lastOneIndex := 0, -1
	for wi, word := range labelBitmap {
		onesCount += bits.OnesCount64(word)
		if word != 0 {
			lastOneIndex = wi<<6 | (63 - bits.LeadingZeros64(word))
		}
	}
	zerosCount := lastOneIndex + 1 - onesCount
	if onesCount != zerosCount+1 || len(labels) != zerosCount {
		return nil, fmt.Errorf("srs: succinct set 损坏")
	}
	if lw := (onesCount + 63) >> 6; len(leaves) < lw {
		leaves = append(leaves, make([]uint64, lw-len(leaves))...)
	}
	return &singDomainSet{newSuccinctBits(leaves, labelBitmap, labels)}, nil
}

type singDomainSet struct{ *succinctBits }

var _ rule.DomainSet = (*singDomainSet)(nil)

func (m *singDomainSet) MatchDomain(domain string) bool {
	return m.has(reverseDomain(domain))
}

// has 逐位移植自 sing common/domain matcher.has。
func (m *singDomainSet) has(key string) bool {
	s := m.succinctBits
	var nodeId, bmIdx int
	for i := 0; i < len(key); i++ {
		currentChar := key[i]
		for ; ; bmIdx++ {
			if getBit(s.labelBitmap, bmIdx) != 0 {
				return false
			}
			nextLabel := s.labels[bmIdx-nodeId]
			if nextLabel == prefixLabel {
				return true
			}
			if nextLabel == rootLabel {
				nextNodeId := s.countZeros(bmIdx + 1)
				if currentChar == '.' && getBit(s.leaves, nextNodeId) != 0 {
					return true
				}
			}
			if nextLabel == currentChar {
				break
			}
		}
		nodeId = s.countZeros(bmIdx + 1)
		bmIdx = s.selectIthOne(nodeId-1) + 1
	}
	if getBit(s.leaves, nodeId) != 0 {
		return true
	}
	for ; ; bmIdx++ {
		if getBit(s.labelBitmap, bmIdx) != 0 {
			return false
		}
		nextLabel := s.labels[bmIdx-nodeId]
		if nextLabel == prefixLabel || nextLabel == rootLabel {
			return true
		}
	}
}

// reverseDomain rune 级反转(与 sing 一致,保多字节字符不乱序)。
func reverseDomain(domain string) string {
	l := len(domain)
	b := make([]byte, l)
	for i := 0; i < l; {
		r, n := utf8.DecodeRuneInString(domain[i:])
		i += n
		utf8.EncodeRune(b[l-i:], r)
	}
	return string(b)
}

// ── srs ip_set:version + uint64 段数 + 每段 [from,to],addr 为 uvarint 长(4/16)+ 字节 ──

func readSRSIPSet(r *bufio.Reader) (*ipAddrRangeSet, error) {
	ver, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if ver != 1 {
		return nil, fmt.Errorf("srs: ip_set 版本 %d≠1", ver)
	}
	var length uint64
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length > 1<<28 {
		return nil, fmt.Errorf("srs: ip_set 段数非法 %d", length)
	}
	s := &ipAddrRangeSet{rr: make([]ipAddrRange, 0, length)}
	for i := uint64(0); i < length; i++ {
		from, err := readSRSAddr(r)
		if err != nil {
			return nil, err
		}
		to, err := readSRSAddr(r)
		if err != nil {
			return nil, err
		}
		s.rr = append(s.rr, ipAddrRange{from.Unmap(), to.Unmap()})
	}
	sort.Slice(s.rr, func(i, j int) bool { return s.rr[i].from.Compare(s.rr[j].from) < 0 })
	return s, nil
}

func readSRSAddr(r *bufio.Reader) (netip.Addr, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return netip.Addr{}, err
	}
	if n != 4 && n != 16 {
		return netip.Addr{}, fmt.Errorf("srs: addr 长度 %d 非法", n)
	}
	var b [16]byte
	if _, err := io.ReadFull(r, b[:n]); err != nil {
		return netip.Addr{}, err
	}
	a, _ := netip.AddrFromSlice(b[:n])
	return a, nil
}

type ipAddrRange struct{ from, to netip.Addr }

type ipAddrRangeSet struct{ rr []ipAddrRange }

var _ rule.IPSet = (*ipAddrRangeSet)(nil)

func (s *ipAddrRangeSet) MatchIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	idx := sort.Search(len(s.rr), func(i int) bool { return s.rr[i].from.Compare(ip) > 0 }) - 1
	return idx >= 0 && ip.Compare(s.rr[idx].to) <= 0
}

// ── varbin 帧读取(uvarint 计数 + 元素) ──

func readUvarU64Slice(r *bufio.Reader) ([]uint64, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if n > 1<<28 {
		return nil, fmt.Errorf("srs: []u64 过长 %d", n)
	}
	s := make([]uint64, n)
	if n > 0 {
		if err := binary.Read(r, binary.BigEndian, s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func readUvarByteSlice(r *bufio.Reader) ([]byte, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if n > 1<<34 {
		return nil, fmt.Errorf("srs: []byte 过长 %d", n)
	}
	s := make([]byte, n)
	if _, err := io.ReadFull(r, s); err != nil {
		return nil, err
	}
	return s, nil
}

// readItemStrings 读 ruleItemString:uvarint 串数 + 每串(uvarint 长 + 字节)。
func readItemStrings(r *bufio.Reader) ([]string, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if n > 1<<24 {
		return nil, fmt.Errorf("srs: 串数过多 %d", n)
	}
	out := make([]string, 0, n)
	for i := uint64(0); i < n; i++ {
		b, err := readUvarByteSlice(r)
		if err != nil {
			return nil, err
		}
		out = append(out, string(b))
	}
	return out, nil
}

func skipUint16Slice(r *bufio.Reader) error {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	_, err = io.CopyN(io.Discard, r, int64(n)*2)
	return err
}

func skipUint8Slice(r *bufio.Reader) error {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	_, err = io.CopyN(io.Discard, r, int64(n))
	return err
}

// ── 并集匹配器 ──

type domainUnion []rule.DomainSet

func (u domainUnion) MatchDomain(h string) bool {
	for _, d := range u {
		if d.MatchDomain(h) {
			return true
		}
	}
	return false
}

type keywordSet []string

func (k keywordSet) MatchDomain(h string) bool {
	for _, kw := range k {
		if bytes.Contains([]byte(h), []byte(kw)) {
			return true
		}
	}
	return false
}

type regexSet []*regexp.Regexp

func (rs regexSet) MatchDomain(h string) bool {
	for _, re := range rs {
		if re.MatchString(h) {
			return true
		}
	}
	return false
}

type ipUnion []rule.IPSet

func (u ipUnion) MatchIP(ip netip.Addr) bool {
	for _, s := range u {
		if s.MatchIP(ip) {
			return true
		}
	}
	return false
}
