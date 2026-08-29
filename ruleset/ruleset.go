// Package ruleset 是规则集提供者:把各家 rule-set 格式(文本 domain-list / ip-list / classical,Surge/Clash 通用)
// 解析成 rule.DomainSet / rule.IPSet 供 rule 引擎消费。来源可为本地文件或经 detour 拉取的远程 URL(抗泄漏)。
// 设计:格式即 reader、引擎零改 —— 加新格式(.srs/.mrs/.json)只是多一个 Parse* 函数,产出同样的 DomainSet/IPSet。
package ruleset

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/rule"
)

// ── 匹配器(与 geo 包同构:域名 exact/suffix/keyword、IP 前缀集) ──

type domainSet struct {
	exact   map[string]struct{}
	suffix  map[string]struct{}
	keyword []string
}

var _ rule.DomainSet = (*domainSet)(nil)

func (d *domainSet) MatchDomain(host string) bool {
	if _, ok := d.exact[host]; ok {
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
	return false
}

type ipSet struct{ prefixes []netip.Prefix }

var _ rule.IPSet = (*ipSet)(nil)

func (s *ipSet) MatchIP(ip netip.Addr) bool {
	for _, p := range s.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func norm(d string) string { return strings.ToLower(strings.TrimSuffix(d, ".")) }

// ── 文本格式解析(Surge DOMAIN-SET / Clash domain·ipcidr·classical payload) ──

// parseDomainLine 把一行域名规则灌进 domainSet。支持:`+.x`/`.x`=后缀、`x`=后缀(列表惯例)、`keyword:x`、`full:x`。
func parseDomainLine(d *domainSet, line string) {
	switch {
	case strings.HasPrefix(line, "full:"):
		d.exact[norm(line[5:])] = struct{}{}
	case strings.HasPrefix(line, "keyword:"):
		d.keyword = append(d.keyword, strings.ToLower(line[8:]))
	case strings.HasPrefix(line, "domain:"):
		d.suffix[norm(line[7:])] = struct{}{}
	case strings.HasPrefix(line, "+."):
		d.suffix[norm(line[2:])] = struct{}{}
	case strings.HasPrefix(line, "."):
		d.suffix[norm(line[1:])] = struct{}{}
	default:
		d.suffix[norm(line)] = struct{}{} // 裸域名按后缀(Surge/Clash domain-list 惯例:匹配该域名及子域)
	}
}

// ParseDomainList 解文本 domain-list(每行一域名;# 注释、空行忽略)→ rule.DomainSet。
func ParseDomainList(data []byte) rule.DomainSet {
	d := &domainSet{exact: map[string]struct{}{}, suffix: map[string]struct{}{}}
	forEachLine(data, func(line string) { parseDomainLine(d, line) })
	return d
}

// ParseIPList 解文本 ip-list → rule.IPSet。兼容:裸 CIDR/IP,以及 Surge RULE-SET 的 `IP-CIDR,1.2.3.0/24[,no-resolve]`。
func ParseIPList(data []byte) rule.IPSet {
	s := &ipSet{}
	forEachLine(data, func(line string) {
		if f := strings.SplitN(line, ",", 3); len(f) >= 2 { // Surge RULE-SET:TYPE,value[,opt]
			if t := strings.ToUpper(strings.TrimSpace(f[0])); t == "IP-CIDR" || t == "IP-CIDR6" {
				line = strings.TrimSpace(f[1])
			}
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			s.prefixes = append(s.prefixes, p)
		} else if ip, err := netip.ParseAddr(line); err == nil {
			s.prefixes = append(s.prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
	})
	return s
}

// ParseClassical 解 Clash/Surge classical(每行 `DOMAIN,x` / `DOMAIN-SUFFIX,x` / `IP-CIDR,x/y` / …)
// → 一个同时可判域名和 IP 的复合集。
func ParseClassical(data []byte) rule.DomainSet {
	d := &domainSet{exact: map[string]struct{}{}, suffix: map[string]struct{}{}}
	forEachLine(data, func(line string) {
		f := strings.SplitN(line, ",", 3)
		if len(f) < 2 {
			return
		}
		val := strings.TrimSpace(f[1])
		switch strings.ToUpper(strings.TrimSpace(f[0])) {
		case "DOMAIN":
			d.exact[norm(val)] = struct{}{}
		case "DOMAIN-SUFFIX":
			d.suffix[norm(val)] = struct{}{}
		case "DOMAIN-KEYWORD":
			d.keyword = append(d.keyword, strings.ToLower(val))
		}
	})
	return d
}

func forEachLine(data []byte, fn func(string)) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 { // 行尾注释
			line = strings.TrimSpace(line[:i])
		}
		fn(line)
	}
}

// ── Provider:本地文件或经 detour 拉取的远程 URL ──

// Provider 是一个规则集来源。Behavior:domain | ipcidr | classical。
type Provider struct {
	Name     string
	Behavior string
	Path     string // 本地文件(与 URL 二选一)
	URL      string // 远程 URL(经 Detour 拉,https)
	Detour   endpoint.Outbound
}

// 格式按魔数自动识别:zstd(28 b5 2f fd)=mihomo .mrs;"SRS"=sing-box .srs;否则文本。
const (
	fmtText = iota
	fmtMRS
	fmtSRS
)

func detectFormat(b []byte) int {
	if len(b) >= 4 && b[0] == 0x28 && b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd {
		return fmtMRS
	}
	if len(b) >= 3 && b[0] == 'S' && b[1] == 'R' && b[2] == 'S' {
		return fmtSRS
	}
	return fmtText
}

// LoadDomain 加载并解析成 DomainSet(behavior=domain/classical)。格式自动识别:文本 / .mrs / .srs。
func (p *Provider) LoadDomain(ctx context.Context) (rule.DomainSet, error) {
	data, err := p.load(ctx)
	if err != nil {
		return nil, err
	}
	switch detectFormat(data) {
	case fmtMRS:
		return ParseMRSDomain(data)
	case fmtSRS:
		return ParseSRSDomain(data)
	}
	if p.Behavior == "classical" {
		return ParseClassical(data), nil
	}
	return ParseDomainList(data), nil
}

// LoadIP 加载并解析成 IPSet(behavior=ipcidr)。格式自动识别:文本 / .mrs / .srs。
func (p *Provider) LoadIP(ctx context.Context) (rule.IPSet, error) {
	data, err := p.load(ctx)
	if err != nil {
		return nil, err
	}
	switch detectFormat(data) {
	case fmtMRS:
		return ParseMRSIP(data)
	case fmtSRS:
		return ParseSRSIP(data)
	}
	return ParseIPList(data), nil
}

func (p *Provider) load(ctx context.Context) ([]byte, error) {
	if p.Path != "" {
		return os.ReadFile(p.Path)
	}
	if p.URL != "" {
		return p.fetch(ctx)
	}
	return nil, fmt.Errorf("ruleset %q: 需 path 或 url", p.Name)
}

// fetch 经 detour 出站拉取远程规则集(https;绝不隐式直连,防泄漏)。
func (p *Provider) fetch(ctx context.Context) ([]byte, error) {
	if p.Detour == nil {
		return nil, fmt.Errorf("ruleset %q: 远程 url 需 detour 出站(绝不隐式直连)", p.Name)
	}
	u, err := url.Parse(p.URL)
	if err != nil {
		return nil, fmt.Errorf("ruleset %q: url:%w", p.Name, err)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	pn, _ := strconv.Atoi(port)
	dst := addr.FromFqdn(host, uint16(pn))
	if ip, e := netip.ParseAddr(host); e == nil {
		dst = addr.FromIPPort(netip.AddrPortFrom(ip, uint16(pn)))
	}
	tr := &http.Transport{DisableKeepAlives: true}
	if u.Scheme == "https" {
		tr.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			s, err := p.Detour.DialStream(ctx, dst)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(s, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = s.Close()
				return nil, err
			}
			return tc, nil
		}
	} else {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return p.Detour.DialStream(ctx, dst)
		}
	}
	defer tr.CloseIdleConnections()
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(rctx, http.MethodGet, p.URL, nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("ruleset %q: 拉取:%w", p.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ruleset %q: HTTP %d", p.Name, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
}
