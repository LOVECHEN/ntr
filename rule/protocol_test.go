package rule

import (
	"net/netip"
	"testing"

	"github.com/LOVECHEN/ntr/addr"
)

// TestProtocolDimension:protocol 维度规则 —— stun→block(任意 IP/端口),其余 proto 走 default;
// 空 proto(未嗅出)不误命中。
func TestProtocolDimension(t *testing.T) {
	e, err := Compile([]Rule{
		{Protocol: []string{"stun"}, To: "block"},
	}, "direct")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	dst := addr.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 19302}
	if g := e.RouteConn(dst, netip.AddrPort{}, "udp", "stun", nil); g != "block" {
		t.Fatalf("stun 应路由到 block,实为 %q", g)
	}
	if g := e.RouteConn(dst, netip.AddrPort{}, "udp", "quic", nil); g != "direct" {
		t.Fatalf("quic 不匹配 stun 规则,应 default direct,实为 %q", g)
	}
	if g := e.RouteConn(dst, netip.AddrPort{}, "udp", "", nil); g != "direct" {
		t.Fatalf("未嗅出协议不应命中,应 default,实为 %q", g)
	}
	// STUN-over-443:端口伪装成 HTTPS 也照拦(protocol 不看端口)。
	dst443 := addr.Socksaddr{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}
	if g := e.RouteConn(dst443, netip.AddrPort{}, "udp", "stun", nil); g != "block" {
		t.Fatalf("STUN-over-443 也应拦到 block,实为 %q", g)
	}
}

// TestProtocolInComposite:protocol 维度可进 and/or 组合(如 udp 且 stun → block)。
func TestProtocolInComposite(t *testing.T) {
	e, err := Compile([]Rule{
		{Op: "and", Sub: []Rule{{Network: []string{"udp"}}, {Protocol: []string{"stun"}}}, To: "block"},
	}, "direct")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	dst := addr.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 3478}
	if g := e.RouteConn(dst, netip.AddrPort{}, "udp", "stun", nil); g != "block" {
		t.Fatalf("udp+stun 组合应到 block,实为 %q", g)
	}
	if g := e.RouteConn(dst, netip.AddrPort{}, "tcp", "stun", nil); g != "direct" {
		t.Fatalf("tcp+stun 不满足 and(需 udp),应 default,实为 %q", g)
	}
}
