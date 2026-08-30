//go:build linux

package service

import (
	"net"
	"net/netip"
	"testing"
)

func TestParseHexIP(t *testing.T) {
	// v4:native-endian(小端)hex → 大端点分。"0100007F" = 小端 0x7F000001 = 127.0.0.1
	if ip, ok := parseHexIP("0100007F"); !ok || ip.String() != "127.0.0.1" {
		t.Errorf("v4 parseHexIP=%v,%v 期望 127.0.0.1", ip, ok)
	}
	// v4:"00000000" = 0.0.0.0
	if ip, ok := parseHexIP("00000000"); !ok || ip.String() != "0.0.0.0" {
		t.Errorf("v4 通配=%v,%v 期望 0.0.0.0", ip, ok)
	}
	// v6:::1 在 /proc/net/tcp6 里是 4 个小端 32 位字 → "00000000000000000000000001000000"
	if ip, ok := parseHexIP("00000000000000000000000001000000"); !ok || ip.String() != "::1" {
		t.Errorf("v6 loopback=%v,%v 期望 ::1", ip, ok)
	}
}

func TestParseHexAddr(t *testing.T) {
	// local_address = "HEXIP:HEXPORT",port 是大端 hex。1F90 = 8080
	ip, port, ok := parseHexAddr("0100007F:1F90")
	if !ok || ip.String() != "127.0.0.1" || port != 8080 {
		t.Errorf("parseHexAddr=%v:%d,%v 期望 127.0.0.1:8080", ip, port, ok)
	}
}

// TestFindProcessSelf:起 listener + 自连,用 client 端本地地址反查发起进程 —— 应命中本测试进程自己。
// 证 /proc 反查链(net/tcp 找 inode → fd 找 pid → exe)在真实 socket 上跑通。
func TestFindProcessSelf(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	srv, err := ln.Accept() // 建立后 socket 才稳定进 /proc/net/tcp
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	src := netip.MustParseAddrPort(conn.LocalAddr().String())
	name, path, ok := procFinder{}.FindProcess("tcp", src)
	if !ok {
		t.Fatalf("反查本进程 socket 失败(src=%v):/proc 链未跑通", src)
	}
	if name == "" || path == "" {
		t.Errorf("反查得空 name=%q path=%q", name, path)
	}
	t.Logf("自连反查:name=%q path=%q", name, path)
}
