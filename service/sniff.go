package service

// 域名嗅探(承第 10 章 §10.4.2):对握手后的客户端流 peek 首包,从 TLS ClientHello 的 SNI 或
// HTTP 请求的 Host 解出真实域名 —— 让「目标只是 IP」的连接(TUN/透明代理/直连 IP)也能按域名分流
// (命中 domain/geosite/rule-set)。peek 用 recordStream 录首包字节,解析后 replay 还给 relay,零丢字节。
// 只读一次首包、带超时(绝不与「你先发我先发」的对端互等死锁);解不出就大声记 fail、按原 dst 走。

import (
	"context"
	"encoding/binary"
	"strings"
	"time"

	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
)

// sniffProtoKey 把嗅探出的应用协议名(小写,如 "stun"/"tls")经 ctx 递给路由解析器 —— 让 protocol 维度
// 规则(routing.rules[].protocol)对【流】与【UDP datagram】统一生效,而 OutboundResolver/ConnResolver
// 的签名不必为此加参(纯 dst/src/network 之外的软信息走 ctx,与 StreamDispatcher 注入同源)。
type sniffProtoKey struct{}

// withSniffedProto 把协议名放进 ctx(空名不放,零成本)。
func withSniffedProto(ctx context.Context, proto string) context.Context {
	if proto == "" {
		return ctx
	}
	return context.WithValue(ctx, sniffProtoKey{}, proto)
}

// sniffedProtoFrom 取出注入的嗅探协议名(无则 "")。
func sniffedProtoFrom(ctx context.Context) string {
	p, _ := ctx.Value(sniffProtoKey{}).(string)
	return p
}

const (
	sniffPeekMax = 4096                   // 首包 peek 上限(TLS ClientHello 常 < 2KB;HTTP 首部通常更小)
	sniffTimeout = 300 * time.Millisecond // peek 超时:首包(TLS/HTTP 客户端都先发)通常即到,超时则按原 dst 走
)

// sniff 对 s peek 首包并解析域名。返回:识别的协议、域名、replay 流(录下的首包字节 + 后续,交给 relay)、失败原因。
// domain 非空即成功;失败时 domain="" 且 replay 仍是完整无损流(按原 dst 继续)。
func sniff(s link.Stream, timeout time.Duration) (endpoint.SniffProto, string, link.Stream, endpoint.SniffFail) {
	rec := &recordStream{Stream: s}
	_ = s.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, sniffPeekMax)
	n, _ := rec.Read(buf) // 录进 rec.buf;replay 时原样吐回
	_ = s.SetReadDeadline(time.Time{})
	replay := rec.replay()
	if n <= 0 {
		return endpoint.SniffNone, "", replay, endpoint.SniffFailTimeout
	}
	data := buf[:n]
	if host, ok := parseTLSSNI(data); ok {
		return endpoint.SniffTLS, host, replay, endpoint.SniffFailNone
	}
	if host, ok := parseHTTPHost(data); ok {
		return endpoint.SniffHTTP, host, replay, endpoint.SniffFailNone
	}
	if isSTUN(data) { // STUN-over-TCP(罕见但完整):无域名,仅供 protocol 规则拦截
		return endpoint.SniffSTUN, "", replay, endpoint.SniffFailNone
	}
	return endpoint.SniffNone, "", replay, endpoint.SniffFailNoMatch
}

// sniffPacket 对一份 UDP datagram 识别应用协议(不 peek、不阻塞:UDP 首包即完整报文)。当前识别 STUN
// (WebRTC/ICE 的 srflx 探测报文)—— 供 protocol 规则拦掉「任何形式 WebRTC → 任何 STUN 地址」,不靠端口/域名/IP
// 名单(对位 sing-box 的 STUN sniffer;xray/mihomo 均无)。识别不出返回 SniffNone。
func sniffPacket(datagram []byte) endpoint.SniffProto {
	if isSTUN(datagram) {
		return endpoint.SniffSTUN
	}
	if isDTLS(datagram) {
		return endpoint.SniffDTLS
	}
	return endpoint.SniffNone
}

// isDTLS 判定一份 UDP 报文是否为 DTLS record(RFC 6347;WebRTC 媒体面 DTLS-SRTP 用之):≥13 字节固定头 +
// content-type ∈ {20 CCS,21 alert,22 handshake,23 appdata,25 heartbeat} + 版本 major=0xfe、
// minor∈{0xff DTLS1.0, 0xfd DTLS1.2}。与 sing-box common/sniff/dtls.go 同判据。配合 STUN 规则可拦整条 WebRTC。
func isDTLS(b []byte) bool {
	if len(b) < 13 {
		return false
	}
	switch b[0] {
	case 20, 21, 22, 23, 25:
	default:
		return false
	}
	return b[1] == 0xfe && (b[2] == 0xff || b[2] == 0xfd)
}

// isSTUN 判定一份报文是否为 STUN(RFC 5389):≥20 字节头 + 魔术 cookie 0x2112A442(bytes[4:8])+ 消息长度
// 字段(bytes[2:4])与实际长度自洽。魔术 cookie 是协议级铁证,不依赖端口(STUN 可跑任意端口含 443)。
// 与 sing-box common/sniff/stun.go 同判据,线级一致。
func isSTUN(b []byte) bool {
	if len(b) < 20 {
		return false
	}
	if binary.BigEndian.Uint32(b[4:8]) != 0x2112A442 {
		return false
	}
	return len(b) >= 20+int(binary.BigEndian.Uint16(b[2:4]))
}

// parseTLSSNI 从 TLS ClientHello 解 server_name(SNI)。手解 record→handshake→extensions(免依赖 crypto/tls 内部)。
func parseTLSSNI(b []byte) (string, bool) {
	// TLS record:[0]=0x16 handshake、[1..2]=version、[3..4]=record 长度。
	if len(b) < 43 || b[0] != 0x16 {
		return "", false
	}
	// handshake:[5]=0x01 ClientHello、[6..8]=长度。跳过 record(5)+hs 头(4)+client version(2)+random(32)=43。
	if b[5] != 0x01 {
		return "", false
	}
	pos := 43
	rd8 := func() (int, bool) {
		if pos+1 > len(b) {
			return 0, false
		}
		v := int(b[pos])
		pos++
		return v, true
	}
	rd16 := func() (int, bool) {
		if pos+2 > len(b) {
			return 0, false
		}
		v := int(b[pos])<<8 | int(b[pos+1])
		pos += 2
		return v, true
	}
	sidLen, ok := rd8() // session_id
	if !ok {
		return "", false
	}
	pos += sidLen
	csLen, ok := rd16() // cipher_suites
	if !ok {
		return "", false
	}
	pos += csLen
	compLen, ok := rd8() // compression_methods
	if !ok {
		return "", false
	}
	pos += compLen
	extTotal, ok := rd16() // extensions 总长
	if !ok {
		return "", false
	}
	end := pos + extTotal
	if end > len(b) {
		end = len(b)
	}
	for pos+4 <= end {
		extType := int(b[pos])<<8 | int(b[pos+1])
		extSize := int(b[pos+2])<<8 | int(b[pos+3])
		pos += 4
		if extType == 0x0000 { // server_name
			// SNI:[0..1]=server_name_list 长、[2]=name_type(0=host_name)、[3..4]=name 长、[5..]=name。
			if pos+5 > len(b) || b[pos+2] != 0x00 {
				return "", false
			}
			nameLen := int(b[pos+3])<<8 | int(b[pos+4])
			if nameLen == 0 || pos+5+nameLen > len(b) {
				return "", false
			}
			host := string(b[pos+5 : pos+5+nameLen])
			if isSaneHost(host) {
				return host, true
			}
			return "", false
		}
		pos += extSize
	}
	return "", false
}

// parseHTTPHost 从明文 HTTP 请求首部解 Host(去端口)。只看首包已有字节,不多读。
func parseHTTPHost(b []byte) (string, bool) {
	// 粗判像 HTTP:首行含 " HTTP/"。
	i := strings.IndexByte(string(b), '\n')
	if i < 0 || !strings.Contains(string(b[:i]), " HTTP/") {
		return "", false
	}
	for _, line := range strings.Split(string(b), "\r\n") {
		if line == "" {
			break // 头结束
		}
		if len(line) > 5 && strings.EqualFold(line[:5], "host:") {
			host := strings.TrimSpace(line[5:])
			if h, _, ok := splitHostPort(host); ok {
				host = h
			}
			if isSaneHost(host) {
				return host, true
			}
			return "", false
		}
	}
	return "", false
}

// splitHostPort 拆 "host:port"(无端口返回原串)。仅用于去 Host 头端口。
func splitHostPort(s string) (host, port string, split bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 || strings.IndexByte(s, ':') != i { // 无冒号 or 多冒号(IPv6 裸址)→ 不拆
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

// isSaneHost 排除 IP 字面量与空串(sniff 出 IP 无意义)+ 明显非法字符。
func isSaneHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	hasAlpha := false
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			hasAlpha = true
		case c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return hasAlpha // 纯数字/点(IP)→ false;含字母的域名 → true
}
