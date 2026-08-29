package geo

// geoip.dat:V2Ray/Xray 的 geoip.dat(protobuf GeoIPList)→ 按国码的 CIDR 集合,供 rule 引擎按 IP 分流。
// 与 mmdb 并列的另一大 IP 库(Xray/sing-box/mihomo 都吃 .dat)。手解 protobuf(protowire,免生成 .pb.go):
//   GeoIPList { repeated GeoIP entry=1; }
//   GeoIP     { string country_code=1; repeated CIDR cidr=2; bool inverse_match=3; }
//   CIDR      { bytes ip=1;  uint32 prefix=2; }   // ip:4 字节=v4,16 字节=v6

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/LOVECHEN/ntr/rule"
)

// GeoIPDatDB 是 geoip.dat 解析结果:国码(大写)→ CIDR 前缀集。
type GeoIPDatDB struct {
	m map[string][]netip.Prefix
}

// OpenGeoIPDat 读并解析 V2Ray geoip.dat。
func OpenGeoIPDat(path string) (*GeoIPDatDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("geo: 读 geoip.dat %q:%w", path, err)
	}
	db := &GeoIPDatDB{m: map[string][]netip.Prefix{}}
	s := data
	for len(s) > 0 {
		num, typ, n := protowire.ConsumeTag(s)
		if n < 0 {
			return nil, fmt.Errorf("geo: geoip.dat 解析错(tag)")
		}
		s = s[n:]
		if num == 1 && typ == protowire.BytesType { // entry
			v, m := protowire.ConsumeBytes(s)
			if m < 0 {
				return nil, fmt.Errorf("geo: geoip.dat 解析错(entry)")
			}
			s = s[m:]
			parseGeoIPEntry(db, v)
		} else {
			m := protowire.ConsumeFieldValue(num, typ, s)
			if m < 0 {
				return nil, fmt.Errorf("geo: geoip.dat 解析错(skip)")
			}
			s = s[m:]
		}
	}
	return db, nil
}

func parseGeoIPEntry(db *GeoIPDatDB, b []byte) {
	var code string
	var pfx []netip.Prefix
	s := b
	for len(s) > 0 {
		num, typ, n := protowire.ConsumeTag(s)
		if n < 0 {
			return
		}
		s = s[n:]
		switch {
		case num == 1 && typ == protowire.BytesType: // country_code
			v, m := protowire.ConsumeBytes(s)
			if m < 0 {
				return
			}
			s = s[m:]
			code = strings.ToUpper(string(v))
		case num == 2 && typ == protowire.BytesType: // cidr
			v, m := protowire.ConsumeBytes(s)
			if m < 0 {
				return
			}
			s = s[m:]
			if p, ok := parseCIDR(v); ok {
				pfx = append(pfx, p)
			}
		default:
			m := protowire.ConsumeFieldValue(num, typ, s)
			if m < 0 {
				return
			}
			s = s[m:]
		}
	}
	if code != "" {
		db.m[code] = append(db.m[code], pfx...)
	}
}

func parseCIDR(b []byte) (netip.Prefix, bool) {
	var ipb []byte
	var prefix uint32
	s := b
	for len(s) > 0 {
		num, typ, n := protowire.ConsumeTag(s)
		if n < 0 {
			return netip.Prefix{}, false
		}
		s = s[n:]
		switch {
		case num == 1 && typ == protowire.BytesType: // ip
			v, m := protowire.ConsumeBytes(s)
			if m < 0 {
				return netip.Prefix{}, false
			}
			s = s[m:]
			ipb = v
		case num == 2 && typ == protowire.VarintType: // prefix
			v, m := protowire.ConsumeVarint(s)
			if m < 0 {
				return netip.Prefix{}, false
			}
			s = s[m:]
			prefix = uint32(v)
		default:
			m := protowire.ConsumeFieldValue(num, typ, s)
			if m < 0 {
				return netip.Prefix{}, false
			}
			s = s[m:]
		}
	}
	ip, ok := netip.AddrFromSlice(ipb)
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(ip.Unmap(), int(prefix)).Masked(), true
}

// CountrySet 返回匹配「IP ∈ ⋃codes 的 CIDR」的 rule.IPSet(codes 大小写不敏感)。
func (db *GeoIPDatDB) CountrySet(codes []string) (rule.IPSet, error) {
	s := &datIPSet{}
	for _, c := range codes {
		c = strings.ToUpper(strings.TrimSpace(c))
		p, ok := db.m[c]
		if !ok {
			return nil, fmt.Errorf("geo: geoip.dat 无国码 %q", c)
		}
		s.prefixes = append(s.prefixes, p...)
	}
	return s, nil
}

type datIPSet struct{ prefixes []netip.Prefix }

var _ rule.IPSet = (*datIPSet)(nil)

func (s *datIPSet) MatchIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range s.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
