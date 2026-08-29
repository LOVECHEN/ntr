//go:build with_tun

package tun

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/LOVECHEN/ntr/core/route"
)

// shouldHijack 报告 dst 是否该被 DNS-hijack:配了 resolver 且 dst 命中劫持地址
// (unspecified:53 = 任意 :53;或精确 IP:53)。命中则不拨出站、由内置 resolver 就地应答。
func (h *Inbound) shouldHijack(dst netip.AddrPort) bool {
	if h.resolver == nil || len(h.hijack) == 0 {
		return false
	}
	for _, a := range h.hijack {
		if a.Port() != dst.Port() {
			continue
		}
		if a.Addr().IsUnspecified() || a.Addr() == dst.Addr() {
			return true
		}
	}
	return false
}

// serveDNSUDP:tun 合成的单目标 UDP 连接上,每个 UDP 包 = 一份 DNS 查询报文;经 resolver 应答后写回。
func (h *Inbound) serveDNSUDP(conn net.Conn) {
	defer conn.Close()
	b := make([]byte, 64*1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(b)
		if err != nil {
			return
		}
		resp, err := h.resolver.Exchange(context.Background(), &route.Message{Raw: append([]byte(nil), b[:n]...)})
		if err != nil || resp == nil || len(resp.Raw) == 0 {
			continue
		}
		if _, err := conn.Write(resp.Raw); err != nil {
			return
		}
	}
}

// serveDNSTCP:TCP DNS 有 2 字节长度前缀([len][报文]);逐条 resolver 应答后按同格式写回。
func (h *Inbound) serveDNSTCP(conn net.Conn) {
	defer conn.Close()
	for {
		var hdr [2]byte
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(conn, q); err != nil {
			return
		}
		resp, err := h.resolver.Exchange(context.Background(), &route.Message{Raw: q})
		if err != nil || resp == nil || len(resp.Raw) == 0 {
			return
		}
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(resp.Raw)))
		if _, err := conn.Write(append(out[:], resp.Raw...)); err != nil {
			return
		}
	}
}
