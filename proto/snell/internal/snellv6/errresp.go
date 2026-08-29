package snellv6

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// snellErrorResponse builds the official server's outbound failure response for a
// failed outbound dial: [0x02 status=error][type byte][len byte][message]
// (sub_3F020). The type byte maps the network errno via byte_1F5FA0; the message
// is the libuv-style error string. Sent as one snell chunk before closing.
//
// errno -> type (byte_1F5FA0): EHOSTUNREACH(113)=8, ECONNREFUSED(111)=6,
// ETIMEDOUT(110)=5, ECONNRESET(104)=4, ENETUNREACH(101)=3, ENETDOWN(100)=2,
// EAFNOSUPPORT(97)=1, everything else = 0xFF.
func snellErrorResponse(err error) []byte {
	// Name-resolution failure -> fixed [0x02][0x64]"DNS Failed" (sub_3DFF0/
	// sub_3E550 -> sub_3DE10(100,"DNS Failed")), regardless of the underlying cause.
	var dnsErr *net.DNSError
	if errors.Is(err, errDNSFailed) || errors.As(err, &dnsErr) {
		msg := "DNS Failed"
		return append([]byte{0x02, 100, byte(len(msg))}, msg...)
	}
	typ := byte(0xFF)
	msg := "unknown error"
	var se syscall.Errno
	switch {
	case errors.As(err, &se):
		switch se {
		case syscall.ECONNREFUSED:
			typ, msg = 6, "connection refused"
		case syscall.ETIMEDOUT:
			typ, msg = 5, "connection timed out"
		case syscall.EHOSTUNREACH:
			typ, msg = 8, "host is unreachable"
		case syscall.ENETUNREACH:
			typ, msg = 3, "network is unreachable"
		case syscall.ECONNRESET:
			typ, msg = 4, "connection reset by peer"
		case syscall.ENETDOWN:
			typ, msg = 2, "network is down"
		case syscall.EAFNOSUPPORT:
			typ, msg = 1, "address family not supported"
		default:
			// libuv uv_strerror fallback (sub_1B7D50): "Unknown system error <N>".
			msg = fmt.Sprintf("Unknown system error %d", int(se))
		}
	case os.IsTimeout(err):
		typ, msg = 5, "connection timed out"
	default:
		msg = err.Error()
	}
	if len(msg) > 255 {
		msg = msg[:255]
	}
	out := make([]byte, 0, 3+len(msg))
	out = append(out, 0x02, typ, byte(len(msg)))
	return append(out, msg...)
}
