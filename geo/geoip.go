// Package geo 是路由的数据源件:geoip(按 IP 归属国分流)。以 rule.IPSet 供 rule 引擎消费,
// I/O(mmdb 读取)全在本包 —— rule 引擎仍是纯函数、只认接口(承设计:核心路由基础设施,非 Band 插件)。
package geo

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang"

	"github.com/LOVECHEN/ntr/rule"
)

// DB 是一个 GeoIP mmdb(MaxMind GeoLite2-Country 格式;mihomo 同款,故可交叉验证)。
type DB struct {
	r *maxminddb.Reader
}

// OpenGeoIP 打开 mmdb 文件。
func OpenGeoIP(path string) (*DB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geo: 打开 geoip mmdb %q:%w", path, err)
	}
	return &DB{r: r}, nil
}

// Close 关闭底层 mmdb。
func (d *DB) Close() error { return d.r.Close() }

// lookupCode 查 ip 的国家 ISO 码(大写);查不到/私有返回空。
func (d *DB) lookupCode(ip netip.Addr) string {
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := d.r.Lookup(net.IP(ip.AsSlice()), &rec); err != nil {
		return ""
	}
	return strings.ToUpper(rec.Country.ISOCode)
}

// CountrySet 返回一个匹配「IP 归属国 ∈ codes」的 rule.IPSet(codes 大小写不敏感)。
func (d *DB) CountrySet(codes []string) rule.IPSet {
	set := make(map[string]struct{}, len(codes))
	for _, c := range codes {
		if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
			set[c] = struct{}{}
		}
	}
	return &countrySet{db: d, codes: set}
}

type countrySet struct {
	db    *DB
	codes map[string]struct{}
}

var _ rule.IPSet = (*countrySet)(nil)

func (c *countrySet) MatchIP(ip netip.Addr) bool {
	code := c.db.lookupCode(ip)
	if code == "" {
		return false
	}
	_, ok := c.codes[code]
	return ok
}
