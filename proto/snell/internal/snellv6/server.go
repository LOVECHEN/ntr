package snellv6

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Server is a Snell v6 server: it accepts client connections, performs the
// handshake + command (PING / CONNECT / CONNECT-reuse / UDP), and relays to the
// requested target. It is the peer of Client and is validated bit-exact against
// the official snell-server. The zero value needs at least PSK set.
type Server struct {
	PSK              []byte                           // pre-shared key (16-255 bytes)
	Mode             Mode                             // b3 encryption mode (default|unshaped|unsafe-raw)
	DNSPreference    string                           // default|prefer-ipv4|prefer-ipv6|ipv4-only|ipv6-only
	DNSServers       []string                         // custom resolvers (config `dns`); empty = system
	HandshakeTimeout time.Duration                    // pre-handshake window, fresh conn (default 10s, sub_401E0)
	ReuseIdleTimeout time.Duration                    // reuse inter-command idle (default 180s, sub_3DC30)
	RelayIdleTimeout time.Duration                    // active relay idle teardown (default 3600s)
	DialTimeout      time.Duration                    // outbound dial timeout; 0 (default) = no app-level timeout (official is transparent: relies on the kernel connect timeout ~127s and the client's own timeout)
	ResolveTimeout   time.Duration                    // DNS resolve deadline; cmd/server config `dns-timeout` 默认置 10s、显式 0 = 不限;直接库用零值 = 不限(≈ c-ares 2s×3 / glibc 5s×2)
	MaxConns         int                              // concurrent connection ceiling (default 4096)
	Logf             func(format string, args ...any) // optional verbose logger
	// Verbose gates the PER-CONNECTION lines that name a proxied destination (CONNECT
	// target, UDP relay, per-datagram errors) — they carry user privacy (who went where,
	// + source IP + clientID). Default false: those lines are suppressed, so a panel/relay
	// embedder doesn't record every user's browsing destinations. Operational lines
	// (service errors, reload) are NOT gated. Matches stock snell-server (destination logs
	// are verbose/debug-only).
	Verbose bool
	// DialControl, if set, is the net.Dialer.Control for outbound connections —
	// used to bind to an egress interface (SO_BINDTODEVICE) per egress-interface.
	DialControl func(network, address string, c syscall.RawConn) error

	initOnce sync.Once
	replay   *replayGuard
	prof     *Profile // PSK-derived profile, computed once (immutable, shared across this server's connections)
}

func (s *Server) init() {
	s.initOnce.Do(func() {
		if s.HandshakeTimeout == 0 {
			s.HandshakeTimeout = 10 * time.Second // official: 10s pre-handshake (sub_401E0)
		}
		if s.ReuseIdleTimeout == 0 {
			s.ReuseIdleTimeout = 180 * time.Second // official: 180s reuse inter-command (sub_3DC30)
		}
		if s.RelayIdleTimeout == 0 {
			s.RelayIdleTimeout = 3600 * time.Second // official: 3600s active relay idle
		}
		// DialTimeout default stays 0 = NO app-level connect timeout, matching the
		// official server (it imposes none — transparent, relies on the kernel
		// connect timeout + the client's own timeout). Set a positive value
		// (config `connect-timeout`) only if you want fast-fail.
		if s.MaxConns == 0 {
			s.MaxConns = 4096
		}
		if s.DNSPreference == "" {
			s.DNSPreference = "default"
		}
		// Derive the PSK profile ONCE (deterministic + immutable); newDecoder/
		// newEncoder share it across every connection instead of re-deriving it
		// per connection (DeriveProfile is the dominant per-connection setup cost).
		s.prof = DeriveProfile(s.PSK)
		s.replay = newReplayGuard()
	})
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// vlogf is logf for PER-CONNECTION destination lines (user-privacy-bearing); it only
// emits when Verbose is set, so an embedder's default log doesn't record every user's
// proxied destinations. See the Verbose field.
func (s *Server) vlogf(format string, args ...any) {
	if s.Verbose && s.Logf != nil {
		s.Logf(format, args...)
	}
}

// chunkDecoder / chunkEncoder are the framing surface the relay loop touches,
// so each framing version plugs in interchangeably (*Receiver/*Sender satisfy
// v6; *ReceiverV5/*SenderV5 satisfy v4+v5). v4 and v5 share one wire protocol
// (verified bit-exact against snell-server v4.1.1 and v5.0.1); they differ only
// in send shaping — v4 splits on a flat 0x3FFF, v5 ramps by MSS.
type chunkDecoder interface {
	DecodeChunk(rd io.Reader) ([]byte, error)
	Salt() [16]byte
	UsesChaCha() bool
}

type chunkEncoder interface {
	EncodeChunk(payload []byte) ([]byte, error)
}

func (s *Server) newDecoder() chunkDecoder {
	r := NewReceiverWithProfile(s.PSK, s.prof)
	r.Mode = s.Mode
	return r
}

func (s *Server) newEncoder(chacha bool) chunkEncoder {
	snd := NewSenderWithProfile(s.PSK, chacha, s.prof)
	snd.Mode = s.Mode
	return snd
}

// commandSizeGate: v6 rejects a stage-S0 command of <=2 bytes (sub_3F640).
func (s *Server) commandSizeGate() bool { return true }

// Serve accepts connections on ln until it errors, handling each concurrently
// (bounded by MaxConns). It tunes accepted sockets like the official server
// (TCP_NODELAY + keepalive).
func (s *Server) Serve(ln net.Listener) error {
	s.init()
	sem := make(chan struct{}, s.MaxConns)
	var tempDelay time.Duration // accept 退避:瞬时错误(EMFILE/ENFILE 等)不打死监听循环
	for {
		c, err := ln.Accept()
		if err != nil {
			// listener 已关闭(正常停服)才真正退出。
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// 瞬时错误退避重试,绝不让单次 accept 错误终结整个监听(对齐 shadowtls 的
			// log-and-continue / 官方 libuv 续 accept,带退避以免持续 fd 耗尽时空转 CPU)。
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if tempDelay > time.Second {
				tempDelay = time.Second
			}
			s.logf("accept error: %v; retrying in %v", err, tempDelay)
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0
		tuneTCP(c)
		// MaxConns 满时 fast-fail:拆掉新连接并记一条,而不是阻塞 accept 循环(阻塞会
		// 让监听看起来挂死且零可观测)。
		select {
		case sem <- struct{}{}:
		default:
			s.logf("[%s] MaxConns(%d) reached, refusing", c.RemoteAddr(), s.MaxConns)
			c.Close()
			continue
		}
		go func() {
			// recover:单条连接的意外 panic(将来若解析路径引入 slice bug)不外溢杀进程。
			defer func() {
				if r := recover(); r != nil {
					s.logf("[%s] panic recovered: %v", c.RemoteAddr(), r)
				}
				c.Close()
				<-sem
			}()
			if err := s.ServeConn(c); err != nil {
				s.logf("[%s] %v", c.RemoteAddr(), err)
			}
		}()
	}
}

// ServeConn handles a single accepted connection: the command loop. A CONNECT
// with command 5 (reuse) keeps the tunnel open after the target closes so the
// client can issue another command; command 1 is single-use.
func (s *Server) ServeConn(client net.Conn) error {
	s.init()
	// NOTE: br is intentionally NOT pooled. serveUDP returns after the FIRST of its
	// two goroutines finishes (`err = <-errc`), leaving the peer goroutine still
	// reading from br — recycling br here would let a later connection's Reset race
	// that lingering read. The relay read buffer (relayBufPool) IS pooled because
	// the TCP relay joins both goroutines before returning.
	br := bufio.NewReader(client)
	recv := s.newDecoder()
	var send chunkEncoder
	checked := false
	firstCmd := true

	for {
		// Idle window awaiting the next command: 10s pre-handshake on a fresh
		// connection (sub_401E0), 180s between commands on a reused command-5
		// tunnel (sub_3DC30). readCommand extends it to the relay idle once the
		// first frame arrives (sub_3F640: re-arm 3600s on the command's first byte).
		idle := s.HandshakeTimeout
		if !firstCmd {
			idle = s.ReuseIdleTimeout
		}
		client.SetReadDeadline(time.Now().Add(idle))
		hdr, initial, err := s.readCommand(recv, br, &checked, client)
		if err != nil {
			return err
		}
		firstCmd = false
		client.SetReadDeadline(time.Time{})
		if send == nil {
			send = s.newEncoder(recv.UsesChaCha()) // match the client's cipher
		}

		switch {
		case hdr.command == cmdPing:
			s.logf("[%s] PING", client.RemoteAddr())
			enc, err := send.EncodeChunk([]byte{0x01}) // pong
			if err != nil {
				return err
			}
			_, err = client.Write(enc)
			return err

		case hdr.command == cmdUDP:
			s.vlogf("[%s] UDP relay user=%q", client.RemoteAddr(), hdr.clientID)
			enc, err := send.EncodeChunk([]byte{0x00}) // ack
			if err != nil {
				return err
			}
			if _, err := client.Write(enc); err != nil {
				return err
			}
			return s.serveUDP(client, br, recv, send)

		default: // CONNECT (command 1 or 5)
			reuse := hdr.command == 5
			target := net.JoinHostPort(hdr.host, strconv.Itoa(int(hdr.port)))
			s.vlogf("[%s] CONNECT user=%q -> %s (reuse=%v)", client.RemoteAddr(), hdr.clientID, target, reuse)
			tc, err := s.dial(target)
			if err != nil {
				// official: send a [0x02][type][len][message] error response, then
				// close (sub_3F020 dial-fail branch), instead of silent close.
				if enc, e := send.EncodeChunk(snellErrorResponse(err)); e == nil {
					client.SetWriteDeadline(time.Now().Add(s.RelayIdleTimeout))
					client.Write(enc)
				}
				return fmt.Errorf("dial %s: %w", target, err)
			}
			if len(initial) > 0 {
				if _, err := tc.Write(initial); err != nil {
					tc.Close()
					return err
				}
			}
			// The official server re-arms the 0x00 status-byte prefix per CONNECT
			// (sub_3F640 line 354 resets ctx+629), including the 2nd+ CONNECT on a
			// reused tunnel — so each CONNECT gets its own first-response flag.
			firstResp := false
			rerr := s.relay(client, br, tc, recv, send, reuse, &firstResp)
			tc.Close()
			if !reuse || rerr != nil {
				return rerr
			}
			// command 5: loop and read the next command on the same tunnel.
			//
			// b3 hardened its E02/E03 reuse-drained predicate (sub_3BBC0 ->
			// sub_3BF90) with a NULL-guard on the decoder's heap input ring-buffer
			// (state+72), since mode state-init calloc's the state and only inits
			// the obfuscation profile for mode=default, leaving that buffer
			// unallocated under unshaped/unsafe-raw. Our decoder reads straight
			// from the *bufio.Reader (no nil ring-buffer field), so the next
			// readCommand simply blocks/EOFs cleanly — there is nothing to guard,
			// and the C guard is itself unreachable-with-NULL anyway (every decoder
			// body allocates that buffer at entry before any drained-status return).
		}
	}
}

// readCommand accumulates decoded chunks until a full stage-S0 command header is
// present, returning it plus any leftover bytes (the request's initial data).
func (s *Server) readCommand(recv chunkDecoder, br *bufio.Reader, checked *bool, client net.Conn) (*command, []byte, error) {
	var buf []byte
	for {
		payload, err := recv.DecodeChunk(br)
		if err != nil {
			return nil, nil, err
		}
		// The pre-handshake/reuse idle window only bounds the wait for the
		// command's FIRST frame; once data flows the official re-arms the 3600s
		// relay idle (sub_3F640 line 242), so a multi-chunk command isn't dropped.
		// Re-arm ONLY on data-bearing chunks: the old `len(buf)==0` guard was reset
		// by every zero-length chunk, so a zero-length-chunk flood could keep the
		// 3600s deadline alive forever and pin the connection (audit). Zero-length
		// frames no longer extend the window → the handshake/reuse deadline bounds them.
		if len(payload) > 0 {
			client.SetReadDeadline(time.Now().Add(s.RelayIdleTimeout))
		}
		// anti-replay: check the handshake salt exactly once. unsafe-raw (mode 2)
		// carries NO salt — the official skips the replay guard for it entirely
		// (sub_40A90 gates the salt-seen check on state[340] != 2).
		if !*checked && s.Mode != ModeUnsafeRaw {
			*checked = true
			if salt := recv.Salt(); s.replay.seenBefore(salt) {
				return nil, nil, fmt.Errorf("replayed salt %x", salt)
			}
		}
		buf = append(buf, payload...)
		h, consumed, err := parseCommand(buf)
		if err != nil {
			return nil, nil, err
		}
		if h != nil {
			// The official rejects a stage-S0 command of <=2 bytes as "Invalid
			// request" (sub_3F640 lines 260-262, inside the stage-S0 branch). On a
			// reused tunnel teardown resets the stage to S0 (sub_3DC30), so the
			// gate applies to EVERY command, not just the first. A bare 2-byte
			// PING is invalid; a real PING carries a 3rd (ignored) byte.
			if s.commandSizeGate() && len(buf) <= 2 {
				return nil, nil, fmt.Errorf("snellv6: invalid request (command %d bytes)", len(buf))
			}
			return h, buf[consumed:], nil
		}
	}
}

// relay relays one CONNECT request both directions until the target is done. A
// zero-length chunk from the client half-closes the target's write side. The
// first response data of the connection is prefixed with a 0x00 status byte
// (sub_3EF60). On target EOF with reuse + prior data, a zero-length chunk is
// sent so the tunnel can carry the next command.
func (s *Server) relay(client net.Conn, br *bufio.Reader, target net.Conn, recv chunkDecoder, send chunkEncoder, reuse bool, firstResp *bool) error {
	idle := s.RelayIdleTimeout
	// relayResult tags which direction finished, so the joiner can do
	// direction-aware teardown (stop the peer goroutine's blocking read instead
	// of letting it hang until RelayIdleTimeout). Wire protocol is unchanged.
	type relayResult struct {
		fromClient bool
		err        error
	}
	done := make(chan relayResult, 2)

	// Deadline arming is mutex-guarded so the joiner's interrupt (SetReadDeadline
	// (now)) can never be overwritten by a goroutine's per-iteration idle re-arm:
	// once a direction is told to stop, it won't re-arm and exits on its next read.
	var muC2T, muT2C sync.Mutex // 每方向独立锁:避免两方向每 chunk 重置 deadline 时互相串行(perf)
	stopC2T, stopT2C := false, false

	go func() { // client -> target
		// recover:中继路径意外 panic 不外溢杀进程;补发 done 让 joiner 不挂、随后拆对端。
		defer func() {
			if r := recover(); r != nil {
				s.logf("[%s] panic in relay client->target: %v", client.RemoteAddr(), r)
				done <- relayResult{fromClient: true, err: fmt.Errorf("panic: %v", r)}
			}
		}()
		var rerr error
		for {
			muC2T.Lock()
			if stopC2T {
				muC2T.Unlock()
				break
			}
			client.SetReadDeadline(time.Now().Add(idle))
			muC2T.Unlock()
			payload, err := recv.DecodeChunk(br)
			if err != nil {
				rerr = err
				break
			}
			if len(payload) == 0 { // zero chunk == client half-close
				break
			}
			target.SetWriteDeadline(time.Now().Add(idle))
			if _, err := target.Write(payload); err != nil {
				rerr = err
				break
			}
		}
		halfCloseWrite(target)
		done <- relayResult{fromClient: true, err: rerr}
	}()

	go func() { // target -> client
		// recover:同上,补发 done 让 joiner 不挂。
		defer func() {
			if r := recover(); r != nil {
				s.logf("[%s] panic in relay target->client: %v", client.RemoteAddr(), r)
				done <- relayResult{fromClient: false, err: fmt.Errorf("panic: %v", r)}
			}
		}()
		var rerr error
		sentData := false
		// Pool the 16 KiB target read buffer: it lives only inside this goroutine
		// and is returned on exit, so under a high connection rate the relay stops
		// allocating 16 KiB per connection (cuts GC pressure). Wire bytes unchanged.
		bp := relayBufPool.Get().(*[]byte)
		defer relayBufPool.Put(bp)
		b := *bp
		for {
			muT2C.Lock()
			if stopT2C {
				muT2C.Unlock()
				break
			}
			target.SetReadDeadline(time.Now().Add(idle))
			muT2C.Unlock()
			n, err := target.Read(b)
			if n > 0 {
				data := b[:n]
				if !*firstResp {
					*firstResp = true
					data = append([]byte{0x00}, data...) // status byte (sub_3EF60)
				}
				enc, e := send.EncodeChunk(data)
				if e != nil {
					rerr = e
					break
				}
				client.SetWriteDeadline(time.Now().Add(idle))
				if _, e := client.Write(enc); e != nil {
					rerr = e
					break
				}
				sentData = true
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					// Target EOF (sub_3EF60 UV_EOF path):
					//   data sent + reuse     -> zero-length chunk ("Sent zero trunk")
					//   data sent + non-reuse -> clean close, no frame
					//   no data   + reuse     -> [02 65 0A]"Remote EOF" error chunk
					//   no data   + non-reuse -> [02 FF 0B]"end of file" error chunk
					sendEOF := true
					var frame []byte
					switch {
					case sentData && reuse:
						frame = nil // zero chunk EOF marker
					case sentData:
						sendEOF = false // non-reuse + data: clean close, no frame
					case reuse:
						frame = append([]byte{0x02, 0x65, byte(len("Remote EOF"))}, "Remote EOF"...)
					default: // no data + non-reuse: libuv UV_EOF, type 0xFF
						frame = append([]byte{0x02, 0xFF, byte(len("end of file"))}, "end of file"...)
					}
					if sendEOF {
						if enc, e := send.EncodeChunk(frame); e == nil {
							client.SetWriteDeadline(time.Now().Add(idle))
							client.Write(enc)
						}
					}
				} else {
					rerr = err
				}
				break
			}
		}
		done <- relayResult{fromClient: false, err: rerr}
	}()

	// Direction-aware teardown (audit #1/#2/#4): when one side is genuinely done,
	// stop the peer's blocking read at once instead of waiting up to
	// RelayIdleTimeout. Wire protocol is unchanged; 3600s is still the idle bound.
	first := <-done
	interrupted := 0 // 1 = interrupted client->target, 2 = interrupted target->client
	switch {
	case !first.fromClient:
		// target side finished (EOF/error) — its EOF frame, if any, was already
		// sent. Unblock client->target so relay returns now.
		muC2T.Lock()
		stopC2T = true
		client.SetReadDeadline(time.Now())
		muC2T.Unlock()
		interrupted = 1
	case first.err != nil:
		// client->target errored (client RST/gone) — unblock target->client.
		muT2C.Lock()
		stopT2C = true
		target.SetReadDeadline(time.Now())
		muT2C.Unlock()
		interrupted = 2
	default:
		// client clean zero-chunk half-close — the target may still be sending its
		// response; keep draining target->client (bounded by its own read idle).
	}
	second := <-done

	// Clear the past deadlines we set to interrupt, so a reused tunnel's next
	// readCommand starts clean (otherwise its first decode would instantly time out).
	client.SetReadDeadline(time.Time{})
	target.SetReadDeadline(time.Time{})

	// Merge errors, ignoring the deadline error caused by our own interrupt.
	var cErr, tErr error
	for _, r := range []relayResult{first, second} {
		if r.fromClient {
			cErr = r.err
		} else {
			tErr = r.err
		}
	}
	if interrupted == 1 && isTimeoutErr(cErr) {
		cErr = nil
	}
	if interrupted == 2 && isTimeoutErr(tErr) {
		tErr = nil
	}
	e := tErr
	if e == nil {
		e = cErr
	}
	if e != nil && !errors.Is(e, io.EOF) {
		return e
	}
	return nil
}

// isTimeoutErr reports whether err is an I/O deadline error. Used to ignore the
// deadline we set on purpose to interrupt the peer relay direction.
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// errDNSFailed is the name-resolution sentinel; snellErrorResponse maps it to
// the official fixed [0x02][0x64]"DNS Failed" frame (sub_3DFF0/sub_3E550 -> sub_3DE10 100).
var errDNSFailed = errors.New("snellv6: DNS Failed")

// dial opens an outbound TCP connection. Unlike net.Dial's Happy-Eyeballs, the
// official server (getaddrinfo cb sub_3DFF0 / c-ares cb sub_3E550) resolves the
// host, selects exactly ONE address by DNSPreference, and connects once to it:
//   - default        : first resolver-ordered address (any family)
//   - prefer-ipv4/6   : first of the preferred family, else first of any family
//   - ipv4-only/6-only: first of that family, else "DNS Failed" (reject)
//
// IP-literal targets skip resolution.
func (s *Server) dial(target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	// KeepAlive:-1 suppresses Go's default SO_KEEPALIVE auto-enable: the official
	// sets only TCP_NODELAY on the target socket (sub_3E390, no uv_tcp_keepalive),
	// unlike the accepted client socket which gets keepalive (sub_3D230).
	d := net.Dialer{Timeout: s.DialTimeout, Control: s.DialControl, KeepAlive: -1}
	if net.ParseIP(host) != nil {
		return d.Dial("tcp", target) // IP literal: no DNS, no preference
	}
	ip, err := s.resolvePreferred(host)
	if err != nil {
		return nil, err
	}
	return d.Dial("tcp", net.JoinHostPort(ip.String(), portStr))
}

// resolvePreferred resolves host and returns the single address chosen per the
// official DNSPreference selection (table dword_1F7490 = {default:0,
// prefer-ipv4:AF_INET, prefer-ipv6:AF_INET6, ipv4-only:AF_INET, ipv6-only:AF_INET6}).
func (s *Server) resolvePreferred(host string) (net.IP, error) {
	// Bound the resolve so an attacker-controlled host pointing at a slow/hung DNS
	// can't pin a ServeConn (TCP) or head-of-line-block a UDP session. Config
	// `dns-timeout` (default 10s); 0 = unbounded. The official relies on c-ares /
	// getaddrinfo query timeouts (c-ares 2s×3, glibc 5s×2) — this matches that.
	ctx := context.Background()
	if s.ResolveTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.ResolveTimeout)
		defer cancel()
	}
	ips, err := s.resolver().LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errDNSFailed
	}
	return selectByPreference(ips, s.DNSPreference)
}

// selectByPreference picks the single outbound address per the official
// DNSPreference rules (sub_3DFF0/sub_3E550, table dword_1F7490={0,2,10,2,10}):
// default → first; prefer-* → first of that family else first of any;
// *-only → first of that family else errDNSFailed. ips is in resolver order.
func selectByPreference(ips []net.IPAddr, pref string) (net.IP, error) {
	isV4 := func(a net.IPAddr) bool { return a.IP.To4() != nil }
	isV6 := func(a net.IPAddr) bool { return a.IP.To4() == nil }
	first := func(pred func(net.IPAddr) bool) net.IP {
		for _, a := range ips {
			if pred == nil || pred(a) {
				return a.IP
			}
		}
		return nil
	}
	switch pref {
	case "ipv4-only":
		if ip := first(isV4); ip != nil {
			return ip, nil
		}
		return nil, errDNSFailed
	case "ipv6-only":
		if ip := first(isV6); ip != nil {
			return ip, nil
		}
		return nil, errDNSFailed
	case "prefer-ipv4":
		if ip := first(isV4); ip != nil {
			return ip, nil
		}
		return first(nil), nil // fall back to first of any family
	case "prefer-ipv6":
		if ip := first(isV6); ip != nil {
			return ip, nil
		}
		return first(nil), nil
	default: // default / first-result
		return first(nil), nil
	}
}

// resolver applies the custom `dns` server list (config key `dns`, sub_551E0)
// and binds DNS query sockets to the egress interface when configured (sub_3D180
// SO_BINDTODEVICE on the c-ares query sockets, "including DNS queries").
func (s *Server) resolver() *net.Resolver {
	if s.DialControl == nil && len(s.DNSServers) == 0 {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Control: s.DialControl}
			if len(s.DNSServers) > 0 {
				// dial the configured DNS servers instead of the system one,
				// trying each in turn.
				var lastErr error
				for _, srv := range s.DNSServers {
					if c, err := d.DialContext(ctx, network, srv); err == nil {
						return c, nil
					} else {
						lastErr = err
					}
				}
				return nil, lastErr
			}
			return d.DialContext(ctx, network, address)
		},
	}
}

// relayBufPool recycles the 16 KiB target→client read buffer across connections.
var relayBufPool = sync.Pool{New: func() any { b := make([]byte, 16384); return &b }}

// tuneTCP applies the accepted-socket options the official server sets
// (sub_3D230: TCP_NODELAY on, keepalive on with a 60s delay).
func tuneTCP(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(60 * time.Second)
	}
}

// halfCloseWrite sends FIN on the write side if the conn supports it.
func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
