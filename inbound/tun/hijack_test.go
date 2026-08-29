//go:build with_tun

package tun

import (
	"context"
	"net/netip"
	"testing"

	"github.com/LOVECHEN/ntr/core/route"
)

type fakeResolver struct{}

func (fakeResolver) LookupCached(string, route.Strategy) ([]netip.Addr, bool) { return nil, false }
func (fakeResolver) Lookup(context.Context, string, route.Strategy) ([]netip.Addr, error) {
	return nil, nil
}
func (fakeResolver) Exchange(context.Context, *route.Message) (*route.Message, error) {
	return nil, nil
}
func (fakeResolver) FakeIPToDomain(netip.Addr) (string, bool) { return "", false }

func TestShouldHijack(t *testing.T) {
	ap := netip.MustParseAddrPort
	// any:53 → 任意 :53 命中,非 53 不命中
	h := &Inbound{resolver: fakeResolver{}, hijack: []netip.AddrPort{ap("0.0.0.0:53")}}
	if !h.shouldHijack(ap("8.8.8.8:53")) {
		t.Fatal("any:53 应命中 8.8.8.8:53")
	}
	if h.shouldHijack(ap("8.8.8.8:443")) {
		t.Fatal("any:53 不应命中 :443")
	}
	// 精确 IP:53
	h2 := &Inbound{resolver: fakeResolver{}, hijack: []netip.AddrPort{ap("10.0.0.1:53")}}
	if !h2.shouldHijack(ap("10.0.0.1:53")) {
		t.Fatal("精确应命中 10.0.0.1:53")
	}
	if h2.shouldHijack(ap("10.0.0.2:53")) {
		t.Fatal("精确不应命中别的 IP")
	}
	// 无 resolver 或无 hijack → 不劫持
	if (&Inbound{hijack: []netip.AddrPort{ap("0.0.0.0:53")}}).shouldHijack(ap("1.1.1.1:53")) {
		t.Fatal("无 resolver 不应劫持")
	}
	if (&Inbound{resolver: fakeResolver{}}).shouldHijack(ap("1.1.1.1:53")) {
		t.Fatal("无 hijack 列表不应劫持")
	}
}
