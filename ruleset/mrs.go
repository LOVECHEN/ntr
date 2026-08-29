package ruleset

// mihomo .mrs 二进制规则集(behavior=domain / ipcidr)。字节级兼容 mihomo:
//   外层 zstd 压缩;内层 = magic "MRS\x01" + behavior(1B) + int64BE count + int64BE extraLen + extra
//   + 载荷:domain → DomainSet.WriteBin(ver1 + []u64 leaves + []u64 labelBitmap + []byte labels)
//           ipcidr → IpCidrSet.WriteBin(ver1 + int64BE 段数 + 每段 [16]from [16]to)
// 源:metacubex/mihomo rules/provider/{mrs_reader,domain_strategy,ipcidr_strategy}.go、component/{trie,cidr}。

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sort"

	"github.com/klauspost/compress/zstd"

	"github.com/LOVECHEN/ntr/rule"
)

var mrsMagic = [4]byte{'M', 'R', 'S', 1}

// ParseMRSDomain 解 behavior=domain 的 .mrs → rule.DomainSet。
func ParseMRSDomain(data []byte) (rule.DomainSet, error) {
	beh, r, err := openMRS(data)
	if err != nil {
		return nil, err
	}
	if beh != 0 {
		return nil, fmt.Errorf("mrs: behavior=%d 非 domain(0)", beh)
	}
	return readDomainSetBin(r)
}

// ParseMRSIP 解 behavior=ipcidr 的 .mrs → rule.IPSet。
func ParseMRSIP(data []byte) (rule.IPSet, error) {
	beh, r, err := openMRS(data)
	if err != nil {
		return nil, err
	}
	if beh != 1 {
		return nil, fmt.Errorf("mrs: behavior=%d 非 ipcidr(1)", beh)
	}
	return readIPCidrSetBin(r)
}

// openMRS zstd 解压 + 校验 magic + 读 behavior/count/extra,返回 behavior 与定位到载荷的 reader。
func openMRS(data []byte) (byte, io.Reader, error) {
	zr, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return 0, nil, fmt.Errorf("mrs: zstd:%w", err)
	}
	// 全量解压到内存(规则集有界),关掉 zstd reader。
	raw, err := io.ReadAll(zr)
	zr.Close()
	if err != nil {
		return 0, nil, fmt.Errorf("mrs: 解压:%w", err)
	}
	r := bytes.NewReader(raw)
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, fmt.Errorf("mrs: 读 magic:%w", err)
	}
	if hdr != mrsMagic {
		return 0, nil, fmt.Errorf("mrs: magic 非法 %v", hdr)
	}
	var beh [1]byte
	if _, err := io.ReadFull(r, beh[:]); err != nil {
		return 0, nil, err
	}
	var count, extraLen int64
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return 0, nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &extraLen); err != nil {
		return 0, nil, err
	}
	if extraLen < 0 || extraLen > int64(r.Len()) {
		return 0, nil, fmt.Errorf("mrs: extraLen 非法 %d", extraLen)
	}
	if extraLen > 0 {
		if _, err := io.CopyN(io.Discard, r, extraLen); err != nil {
			return 0, nil, err
		}
	}
	return beh[0], r, nil
}

// readDomainSetBin 读 DomainSet.WriteBin 载荷 → succinctDomainSet(对齐 mihomo ReadDomainSetBin)。
func readDomainSetBin(r io.Reader) (rule.DomainSet, error) {
	var ver [1]byte
	if _, err := io.ReadFull(r, ver[:]); err != nil {
		return nil, err
	}
	if ver[0] != 1 {
		return nil, fmt.Errorf("mrs: DomainSet 版本 %d≠1", ver[0])
	}
	leaves, err := readU64Slice(r)
	if err != nil {
		return nil, err
	}
	labelBitmap, err := readU64Slice(r)
	if err != nil {
		return nil, err
	}
	var n int64
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n < 1 || n > 1<<34 {
		return nil, fmt.Errorf("mrs: labels 长度非法 %d", n)
	}
	labels := make([]byte, n)
	if _, err := io.ReadFull(r, labels); err != nil {
		return nil, err
	}
	return newSuccinctDomainSet(leaves, labelBitmap, labels), nil
}

func readU64Slice(r io.Reader) ([]uint64, error) {
	var n int64
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n < 1 || n > 1<<28 {
		return nil, fmt.Errorf("mrs: []u64 长度非法 %d", n)
	}
	s := make([]uint64, n)
	if err := binary.Read(r, binary.BigEndian, s); err != nil {
		return nil, err
	}
	return s, nil
}

// ── ipcidr:排序的 [from,to] 16 字节区间集,二分判定包含(对齐 mihomo cidr.IpCidrSet) ──

type ipRange struct{ from, to [16]byte }

type ipRangeSet struct{ rr []ipRange }

var _ rule.IPSet = (*ipRangeSet)(nil)

func readIPCidrSetBin(r io.Reader) (rule.IPSet, error) {
	var ver [1]byte
	if _, err := io.ReadFull(r, ver[:]); err != nil {
		return nil, err
	}
	if ver[0] != 1 {
		return nil, fmt.Errorf("mrs: IpCidrSet 版本 %d≠1", ver[0])
	}
	var n int64
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n < 0 || n > 1<<28 {
		return nil, fmt.Errorf("mrs: cidr 段数非法 %d", n)
	}
	s := &ipRangeSet{rr: make([]ipRange, n)}
	for i := range s.rr {
		if _, err := io.ReadFull(r, s.rr[i].from[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(r, s.rr[i].to[:]); err != nil {
			return nil, err
		}
	}
	// mihomo 写出即已 Merge()(升序、不重叠),仍稳妥再排一次保二分前提。
	sort.Slice(s.rr, func(i, j int) bool { return bytes.Compare(s.rr[i].from[:], s.rr[j].from[:]) < 0 })
	return s, nil
}

func (s *ipRangeSet) MatchIP(ip netip.Addr) bool {
	t := ip.As16() // v4 走 ::ffff:a.b.c.d,与 mihomo r.From().As16() 一致
	// 找最后一个 from<=t 的段,再判 t<=to。
	idx := sort.Search(len(s.rr), func(i int) bool { return bytes.Compare(s.rr[i].from[:], t[:]) > 0 }) - 1
	return idx >= 0 && bytes.Compare(t[:], s.rr[idx].to[:]) <= 0
}
