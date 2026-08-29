package geo

// geosite:V2Ray/mihomo 的 geosite.dat(protobuf GeoSiteList)→ 按国码/类目的域名集合,供 rule 引擎按域名分流。
// 手解 protobuf(google.golang.org/protobuf/encoding/protowire,已在依赖树)—— 三层小消息,免生成 .pb.go。
//   GeoSiteList { repeated GeoSite entry=1; }
//   GeoSite     { string country_code=1; repeated Domain domain=2; }
//   Domain      { Type type=1[Plain=0,Regex=1,Domain=2,Full=3]; string value=2; }

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/LOVECHEN/ntr/rule"
)

type geositeDomain struct {
	typ   int
	value string
}

// GeoSiteDB 是 geosite.dat 解析结果:类目码(大写)→ 域名条目。
type GeoSiteDB struct {
	m map[string][]geositeDomain
}

// OpenGeoSite 读并解析 geosite.dat。
func OpenGeoSite(path string) (*GeoSiteDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("geo: 读 geosite.dat %q:%w", path, err)
	}
	db := &GeoSiteDB{m: map[string][]geositeDomain{}}
	s := data
	for len(s) > 0 {
		num, typ, n := protowire.ConsumeTag(s)
		if n < 0 {
			return nil, fmt.Errorf("geo: geosite.dat 解析错(tag)")
		}
		s = s[n:]
		if num == 1 && typ == protowire.BytesType { // entry
			v, m := protowire.ConsumeBytes(s)
			if m < 0 {
				return nil, fmt.Errorf("geo: geosite.dat 解析错(entry)")
			}
			s = s[m:]
			parseGeoSiteEntry(db, v)
		} else {
			m := protowire.ConsumeFieldValue(num, typ, s)
			if m < 0 {
				return nil, fmt.Errorf("geo: geosite.dat 解析错(skip)")
			}
			s = s[m:]
		}
	}
	return db, nil
}

func parseGeoSiteEntry(db *GeoSiteDB, b []byte) {
	var code string
	var doms []geositeDomain
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
		case num == 2 && typ == protowire.BytesType: // domain
			v, m := protowire.ConsumeBytes(s)
			if m < 0 {
				return
			}
			s = s[m:]
			doms = append(doms, parseDomain(v))
		default:
			m := protowire.ConsumeFieldValue(num, typ, s)
			if m < 0 {
				return
			}
			s = s[m:]
		}
	}
	if code != "" {
		db.m[code] = doms
	}
}

func parseDomain(b []byte) geositeDomain {
	var d geositeDomain
	s := b
	for len(s) > 0 {
		num, typ, n := protowire.ConsumeTag(s)
		if n < 0 {
			return d
		}
		s = s[n:]
		switch {
		case num == 1 && typ == protowire.VarintType: // type
			v, m := protowire.ConsumeVarint(s)
			if m < 0 {
				return d
			}
			s = s[m:]
			d.typ = int(v)
		case num == 2 && typ == protowire.BytesType: // value
			v, m := protowire.ConsumeBytes(s)
			if m < 0 {
				return d
			}
			s = s[m:]
			d.value = string(v)
		default:
			m := protowire.ConsumeFieldValue(num, typ, s)
			if m < 0 {
				return d
			}
			s = s[m:]
		}
	}
	return d
}

// DomainSet 建某类目码(如 google / cn)的 rule.DomainSet:Full→精确、Domain→后缀、Plain→关键字、Regex→正则。
func (db *GeoSiteDB) DomainSet(code string) (rule.DomainSet, error) {
	doms, ok := db.m[strings.ToUpper(code)]
	if !ok {
		return nil, fmt.Errorf("geo: geosite 无类目 %q", code)
	}
	ds := &domainSet{full: map[string]struct{}{}, suffix: map[string]struct{}{}}
	for _, d := range doms {
		switch d.typ {
		case 3: // Full → 精确
			ds.full[normDomainG(d.value)] = struct{}{}
		case 2: // Domain(RootDomain) → 后缀(标签边界)
			ds.suffix[normDomainG(d.value)] = struct{}{}
		case 0: // Plain → 关键字
			ds.keyword = append(ds.keyword, strings.ToLower(d.value))
		case 1: // Regex → 正则
			if re, err := regexp.Compile(d.value); err == nil {
				ds.regex = append(ds.regex, re)
			}
		}
	}
	return ds, nil
}

type domainSet struct {
	full    map[string]struct{}
	suffix  map[string]struct{}
	keyword []string
	regex   []*regexp.Regexp
}

var _ rule.DomainSet = (*domainSet)(nil)

func (d *domainSet) MatchDomain(host string) bool {
	if _, ok := d.full[host]; ok {
		return true
	}
	for s := host; s != ""; {
		if _, ok := d.suffix[s]; ok {
			return true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	for _, k := range d.keyword {
		if strings.Contains(host, k) {
			return true
		}
	}
	for _, re := range d.regex {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

func normDomainG(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
