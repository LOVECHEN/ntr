package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	mtls "github.com/metacubex/tls"
	mquic "github.com/metacubex/quic-go"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

type upstreamKind uint8

const (
	kindUDP upstreamKind = iota // udp://IP:53   明文 UDP
	kindTCP                     // tcp://IP:53   明文 TCP
	kindDoT                     // tls://IP:853  DNS-over-TLS
	kindDoH                     // https://IP/dns-query  DNS-over-HTTPS
	kindDoQ                     // quic://IP:853  DNS-over-QUIC(RFC 9250)
)

// upstream 是一台上游 nameserver:承载 + 地址 + 绑定的具名出站(detour,防 DNS 泄漏)。
type upstream struct {
	tag      string
	kind     upstreamKind
	dst      addr.Socksaddr // 拨号目标(IP:port)
	sni      string         // DoT/DoH 的 TLS ServerName(默认=host;IP 时靠 IP SAN 校验)
	dohURL   string         // DoH 完整 URL
	insecure bool           // 跳过证书校验(自签/测试)
	detour   endpoint.Outbound
}

// parseNameserver 解析 nameserver 地址。MVP 承载:udp/tcp(明文)+ tls(DoT)+ https(DoH);DoQ 为后续。
//
//	udp://IP:53 · tcp://IP:53 · tls://IP:853 · https://IP/dns-query
//
// sniOverride 非空则覆盖 TLS ServerName(host 为域名时须配 bootstrap;MVP 建议直接用 IP,靠 IP SAN 校验)。
func parseNameserver(address, sniOverride string, insecure bool) (u upstream, err error) {
	scheme := "udp"
	rest := address
	if i := strings.Index(address, "://"); i >= 0 {
		scheme = address[:i]
		rest = address[i+3:]
	}
	u.sni = sniOverride
	u.insecure = insecure
	switch scheme {
	case "udp":
		u.kind = kindUDP
	case "tcp":
		u.kind = kindTCP
	case "tls", "dot":
		u.kind = kindDoT
	case "https", "doh", "h2":
		u.kind = kindDoH
	case "quic", "doq", "h3":
		u.kind = kindDoQ
	default:
		return u, fmt.Errorf("dns: 未知 nameserver 承载 %q", scheme)
	}

	if u.kind == kindDoH {
		full := address
		if !strings.Contains(full, "://") {
			full = "https://" + full
		}
		pu, e := url.Parse(full)
		if e != nil {
			return u, fmt.Errorf("dns: DoH URL %q:%w", address, e)
		}
		host := pu.Hostname()
		port := pu.Port()
		if port == "" {
			port = "443"
		}
		if pu.Path == "" {
			pu.Path = "/dns-query"
		}
		u.dst, err = hostPortToAddr(host, port)
		if err != nil {
			return u, err
		}
		if u.sni == "" {
			u.sni = host
		}
		pu.Host = net.JoinHostPort(host, port)
		u.dohURL = pu.String()
		return u, nil
	}

	// udp/tcp/tls/quic:rest = IP[:port]
	host, port := splitHostPort(rest, defaultPort(u.kind))
	u.dst, err = hostPortToAddr(host, port)
	if err != nil {
		return u, err
	}
	if (u.kind == kindDoT || u.kind == kindDoQ) && u.sni == "" {
		u.sni = host
	}
	return u, nil
}

func defaultPort(k upstreamKind) string {
	if k == kindDoT || k == kindDoQ {
		return "853"
	}
	return "53"
}

func splitHostPort(s, defPort string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return s, defPort
}

func hostPortToAddr(host, port string) (addr.Socksaddr, error) {
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return addr.Socksaddr{}, fmt.Errorf("dns: 端口非法 %q", port)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return addr.FromIPPort(netip.AddrPortFrom(ip, uint16(p))), nil
	}
	// 域名:交出站解析(须 bootstrap;MVP 建议 IP 字面量)。
	return addr.FromFqdn(host, uint16(p)), nil
}

// query 向本上游发一份 DNS 报文并取回应答(经 detour 出站,绝不隐式直连)。
func (u *upstream) query(ctx context.Context, raw []byte) ([]byte, error) {
	switch u.kind {
	case kindTCP:
		return u.queryTCP(ctx, raw)
	case kindDoT:
		return u.queryDoT(ctx, raw)
	case kindDoH:
		return u.queryDoH(ctx, raw)
	case kindDoQ:
		return u.queryDoQ(ctx, raw)
	default:
		return u.queryUDP(ctx, raw)
	}
}

func (u *upstream) queryUDP(ctx context.Context, raw []byte) ([]byte, error) {
	pc, err := u.detour.DialPacket(ctx, u.dst)
	if err != nil {
		return nil, fmt.Errorf("dns[%s]: 拨上游 UDP:%w", u.tag, err)
	}
	defer pc.Close()
	wb := buf.New()
	_, _ = wb.Write(raw)
	err = pc.WritePacket(wb, u.dst)
	wb.Release()
	if err != nil {
		return nil, fmt.Errorf("dns[%s]: 发查询:%w", u.tag, err)
	}
	rb := buf.New()
	defer rb.Release()
	if _, err := pc.ReadPacket(rb); err != nil {
		return nil, fmt.Errorf("dns[%s]: 收应答:%w", u.tag, err)
	}
	return append([]byte(nil), rb.Bytes()...), nil
}

func (u *upstream) queryTCP(ctx context.Context, raw []byte) ([]byte, error) {
	s, err := u.detour.DialStream(ctx, u.dst)
	if err != nil {
		return nil, fmt.Errorf("dns[%s]: 拨上游 TCP:%w", u.tag, err)
	}
	defer s.Close()
	return dnsOverStream(s, raw, u.tag)
}

func (u *upstream) queryDoT(ctx context.Context, raw []byte) ([]byte, error) {
	s, err := u.detour.DialStream(ctx, u.dst)
	if err != nil {
		return nil, fmt.Errorf("dns[%s]: 拨上游 DoT:%w", u.tag, err)
	}
	defer s.Close()
	tconn := tls.Client(s, &tls.Config{ServerName: u.sni, InsecureSkipVerify: u.insecure, MinVersion: tls.VersionTLS12})
	if err := tconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("dns[%s]: DoT 握手:%w", u.tag, err)
	}
	return dnsOverStream(tconn, raw, u.tag) // DoT 就是 TLS 里的 DNS-over-TCP(2 字节长度分帧)
}

func (u *upstream) queryDoH(ctx context.Context, raw []byte) ([]byte, error) {
	// 每查询一条 TLS 连接(经 detour);MVP 不池化。DialTLSContext 忽略 http 传入的 addr,固定拨 detour→dst。
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			s, err := u.detour.DialStream(ctx, u.dst)
			if err != nil {
				return nil, err
			}
			tconn := tls.Client(s, &tls.Config{ServerName: u.sni, InsecureSkipVerify: u.insecure, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
			if err := tconn.HandshakeContext(ctx); err != nil {
				_ = s.Close()
				return nil, err
			}
			return tconn, nil
		},
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.dohURL, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("dns[%s]: DoH 建请求:%w", u.tag, err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("dns[%s]: DoH 请求:%w", u.tag, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dns[%s]: DoH 状态 %d", u.tag, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

// queryDoQ 做 DNS-over-QUIC(RFC 9250):对上游拨 QUIC(ALPN "doq"),每查询开一条双向流,写
// [2 字节长度][报文] 后半关发送侧,读回 [2 字节长度][应答]。经 detour 的 UDP(适配成 net.PacketConn)。
// RFC 9250 §4.2.1:DoQ 上查询报文的 Message ID 必须为 0(流本身提供关联)—— 故送前清零、收后还原。
func (u *upstream) queryDoQ(ctx context.Context, raw []byte) ([]byte, error) {
	pc, err := u.detour.DialPacket(ctx, u.dst)
	if err != nil {
		return nil, fmt.Errorf("dns[%s]: 拨上游 DoQ(UDP):%w", u.tag, err)
	}
	npc := &pktConnAdapter{pc: pc, dst: u.dst, remote: udpAddrOf(u.dst)}
	defer npc.Close()

	tlsCfg := &mtls.Config{ServerName: u.sni, InsecureSkipVerify: u.insecure, NextProtos: []string{"doq"}, MinVersion: mtls.VersionTLS13}
	conn, err := mquic.Dial(ctx, npc, npc.remote, tlsCfg, &mquic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("dns[%s]: DoQ 拨号:%w", u.tag, err)
	}
	defer conn.CloseWithError(0, "")
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("dns[%s]: DoQ 开流:%w", u.tag, err)
	}
	// 送前清零 Message ID(DoQ 要求),收后还原成原查询 ID。
	origID := uint16(0)
	q := raw
	if len(raw) >= 2 {
		origID = binary.BigEndian.Uint16(raw[0:2])
		q = append([]byte(nil), raw...)
		binary.BigEndian.PutUint16(q[0:2], 0)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(q)))
	if _, err := st.Write(append(hdr[:], q...)); err != nil {
		return nil, fmt.Errorf("dns[%s]: DoQ 发查询:%w", u.tag, err)
	}
	_ = st.Close() // 半关发送侧(FIN),对端据此知查询完整
	if _, err := io.ReadFull(st, hdr[:]); err != nil {
		return nil, fmt.Errorf("dns[%s]: DoQ 读长度:%w", u.tag, err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(st, resp); err != nil {
		return nil, fmt.Errorf("dns[%s]: DoQ 读应答:%w", u.tag, err)
	}
	if len(resp) >= 2 { // 还原 Message ID
		binary.BigEndian.PutUint16(resp[0:2], origID)
	}
	return resp, nil
}

// pktConnAdapter 把单目标 link.PacketConn 适配成 net.PacketConn(供 quic-go 在 detour 的 UDP 上跑 QUIC)。
// 单目标语义:WriteTo 忽略传入 addr(恒发 dst)、ReadFrom 回报固定 remote。
type pktConnAdapter struct {
	pc     link.PacketConn
	dst    addr.Socksaddr
	remote net.Addr
}

func (a *pktConnAdapter) ReadFrom(p []byte) (int, net.Addr, error) {
	b := buf.New()
	defer b.Release()
	if _, err := a.pc.ReadPacket(b); err != nil {
		return 0, nil, err
	}
	return copy(p, b.Bytes()), a.remote, nil
}

func (a *pktConnAdapter) WriteTo(p []byte, _ net.Addr) (int, error) {
	b := buf.New()
	defer b.Release()
	if _, err := b.Write(p); err != nil {
		return 0, err
	}
	if err := a.pc.WritePacket(b, a.dst); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (a *pktConnAdapter) Close() error                       { return a.pc.Close() }
func (a *pktConnAdapter) LocalAddr() net.Addr                { return a.pc.LocalAddr() }
func (a *pktConnAdapter) SetDeadline(t time.Time) error      { return a.pc.SetDeadline(t) }
func (a *pktConnAdapter) SetReadDeadline(t time.Time) error  { return a.pc.SetDeadline(t) }
func (a *pktConnAdapter) SetWriteDeadline(t time.Time) error { return nil }

// udpAddrOf 把 Socksaddr 转 *net.UDPAddr(DoQ 的远端)。
func udpAddrOf(d addr.Socksaddr) net.Addr {
	if d.IsIP() {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(d.Addr, d.Port))
	}
	return &net.UDPAddr{IP: net.ParseIP(d.Host()), Port: int(d.Port)}
}

// dnsOverStream 在一条(可 TLS 的)可靠流上做 DNS-over-TCP(2 字节长度前缀)。
func dnsOverStream(s io.ReadWriter, raw []byte, tag string) ([]byte, error) {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(raw)))
	if _, err := s.Write(append(hdr[:], raw...)); err != nil {
		return nil, fmt.Errorf("dns[%s]: 发查询:%w", tag, err)
	}
	if _, err := io.ReadFull(s, hdr[:]); err != nil {
		return nil, fmt.Errorf("dns[%s]: 读长度:%w", tag, err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(s, resp); err != nil {
		return nil, fmt.Errorf("dns[%s]: 读应答:%w", tag, err)
	}
	return resp, nil
}
