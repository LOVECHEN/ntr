package snellv6

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// udpIdleTimeout is the single connection-wide idle timer, re-armed on every
// decoded REQUEST chunk (sub_3F640 lines 242/404 -> uv_timer_start(sub_3EDE0,
// 3600000ms)). The return socket has no timer (sub_40980 recv_start, no timeout).
const udpIdleTimeout = 3600 * time.Second

// serveUDP handles command-6 UDP-relay sessions. Each decoded snell chunk is one
// request frame; each datagram received on the relay socket is framed back to
// the client. Frame formats (reversed from sub_40A60 / sub_40380):
//
//	request  (client->server): [01][addrLen][host | 00 type addr][port BE][data]
//	  addrLen>0 : host is a `addrLen`-byte domain string
//	  addrLen==0: next byte is type (4=IPv4 → 4B addr, 6=IPv6 → 16B addr)
//	response (server->client): [type 4|6][raw addr 4|16][port BE][data]
func (s *Server) serveUDP(client net.Conn, br *bufio.Reader, recv chunkDecoder, send chunkEncoder) error {
	// The official binds the UDP relay socket to the egress-interface too
	// (sub_41DE0 -> sub_3D710 SO_BINDTODEVICE, "Bind outgoing TCP, UDP, and DNS
	// sockets to the named interface"), so reuse the same egress control the TCP
	// dial uses. s.DialControl is nil / a no-op when no egress-interface is set.
	pc, err := (&net.ListenConfig{Control: s.DialControl}).ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return err
	}
	relay := pc.(*net.UDPConn)
	defer relay.Close()

	errc := make(chan error, 2)

	// target -> client (return socket: no idle timer in the official, sub_40980)
	go func() {
		// recover:补发 errc 让主体不挂、随后 Close 解阻塞对端。
		defer func() {
			if r := recover(); r != nil {
				s.logf("[udp %s] panic target->client: %v", client.RemoteAddr(), r)
				errc <- fmt.Errorf("panic: %v", r)
			}
		}()
		buf := make([]byte, 65535)
		for {
			n, src, err := relay.ReadFromUDP(buf)
			if err != nil {
				errc <- err
				return
			}
			frame := buildUDPResponse(src, buf[:n])
			enc, e := send.EncodeChunk(frame)
			if e != nil {
				errc <- e
				return
			}
			// Bound the write like the TCP relay does (server.go relay): a client
			// that stops reading (zero window) must not pin this return goroutine +
			// UDP socket + 64KB buffer forever. SetReadDeadline on the other goroutine
			// can't interrupt a blocked Write here, so cap it explicitly.
			client.SetWriteDeadline(time.Now().Add(s.RelayIdleTimeout))
			if _, e := client.Write(enc); e != nil {
				errc <- e
				return
			}
		}
	}()

	// client -> target. The DecodeChunk read deadline is the single idle timer,
	// re-armed per request chunk (sub_3F640 -> uv_timer_start 3600s).
	go func() {
		// recover:同上,补发 errc。
		defer func() {
			if r := recover(); r != nil {
				s.logf("[udp %s] panic client->target: %v", client.RemoteAddr(), r)
				errc <- fmt.Errorf("panic: %v", r)
			}
		}()
		cache := map[string]*net.UDPAddr{} // per-session resolved-address cache
		for {
			client.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			payload, err := recv.DecodeChunk(br)
			if err != nil {
				errc <- err
				return
			}
			if len(payload) == 0 {
				continue
			}
			target, data, err := parseUDPFrame(payload)
			if err != nil {
				if errors.Is(err, errUDPBadCommand) {
					// "Unsupport UDP command" -> sn_server_tunnel_close_all:
					// a bad command byte tears down the whole tunnel (sub_40A60:72-77).
					errc <- err
					return
				}
				continue // other malformed frame: drop, keep session alive
			}
			addr, err := s.resolveUDP(target, cache)
			if err != nil {
				continue // DNS failure: drop (mirrors per-host drop, sub_405F0)
			}
			// best-effort 转发(单包失败不拆会话,对齐 sub_405F0 per-host drop);
			// 但失败记一条 verbose 日志,便于排查 EMSGSIZE/ENOBUFS/ICMP unreachable。
			if _, err := relay.WriteToUDP(data, addr); err != nil {
				s.vlogf("[udp %s] WriteToUDP %s: %v", client.RemoteAddr(), addr, err)
			}
		}
	}()

	err = <-errc
	relay.Close()
	client.Close()
	return err
}

// resolveUDP resolves host:port honoring DNSPreference (sub_40A60 sets the
// c-ares ai_family hint from the preference; sub_405F0 filters the result). The
// resolve is bounded by the `dns-timeout` deadline inside resolvePreferred (so a
// slow/hung resolver can't head-of-line-block the UDP session), plus a
// per-session cache so a host isn't re-resolved per datagram. IP literals resolve
// instantly.
func (s *Server) resolveUDP(target string, cache map[string]*net.UDPAddr) (*net.UDPAddr, error) {
	if a, ok := cache[target]; ok {
		return a, nil
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	if ip := net.ParseIP(host); ip != nil {
		// IP literals re-parse instantly — do NOT cache them. Otherwise a single session
		// streaming datagrams to millions of distinct IP:port targets would grow this map
		// without bound (one authenticated user → unbounded RSS). No DNS, no caching needed.
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	ip, err := s.resolvePreferred(host) // same per-family selection as TCP dial
	if err != nil {
		return nil, errUDPFrame
	}
	a := &net.UDPAddr{IP: ip, Port: port}
	// Bound the DNS-result cache. Over the cap, re-resolve per datagram (a CPU cost for a
	// pathological distinct-host client, never unbounded memory). Real clients hit a small
	// stable target set and stay well under the cap, so their behavior is unchanged.
	if len(cache) < udpResolveCacheMax {
		cache[target] = a
	}
	return a, nil
}

// udpResolveCacheMax caps the per-session DNS-result cache (see resolveUDP).
const udpResolveCacheMax = 4096

var (
	errUDPFrame      = errors.New("snellv6: malformed UDP frame")
	errUDPBadCommand = errors.New("snellv6: unsupported UDP command byte") // frame[0] != 1
)

// parseUDPFrame extracts (target "host:port", payload) from a request frame.
func parseUDPFrame(b []byte) (string, []byte, error) {
	if len(b) < 1 || b[0] != 1 {
		return "", nil, errUDPBadCommand // "Unsupport UDP command" -> full teardown
	}
	if len(b) < 2 {
		return "", nil, errUDPFrame
	}
	addrLen := int(b[1])
	if addrLen != 0 {
		// hostname form. The binary requires framesize >= addrLen+5, i.e. at
		// least one data byte after host(addrLen)+port(2) (sub_40380/sub_40A60:
		// reject when addrLen+4 >= framesize) — a zero-data hostname frame is
		// rejected, NOT forwarded as an empty datagram.
		q := 2 + addrLen
		if len(b) < q+3 {
			return "", nil, errUDPFrame
		}
		host := string(b[2:q])
		port := binary.BigEndian.Uint16(b[q : q+2])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), b[q+2:], nil
	}
	// IP form: [01][00][type][addr][port]
	if len(b) < 3 {
		return "", nil, errUDPFrame
	}
	switch b[2] {
	case 4:
		if len(b) < 9 {
			return "", nil, errUDPFrame
		}
		ip := net.IP(b[3:7])
		port := binary.BigEndian.Uint16(b[7:9])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), b[9:], nil
	case 6:
		if len(b) < 21 {
			return "", nil, errUDPFrame
		}
		ip := net.IP(b[3:19])
		port := binary.BigEndian.Uint16(b[19:21])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), b[21:], nil
	default:
		return "", nil, errUDPFrame
	}
}

// buildUDPResponse frames a datagram from `src` back to the client.
func buildUDPResponse(src *net.UDPAddr, data []byte) []byte {
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(src.Port))
	if ip4 := src.IP.To4(); ip4 != nil {
		out := make([]byte, 0, 7+len(data))
		out = append(out, 4)
		out = append(out, ip4...)
		out = append(out, pb[:]...)
		return append(out, data...)
	}
	out := make([]byte, 0, 19+len(data))
	out = append(out, 6)
	out = append(out, src.IP.To16()...)
	out = append(out, pb[:]...)
	return append(out, data...)
}
