package service

import (
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/LOVECHEN/ntr/rule"
)

// procFinder 是 Linux 上的 rule.ProcessFinder:由连接源地址(client 侧本地 ip:port)反查发起进程。
//
// 两步(纯 /proc,无 CGO,合瘦核心 CGO=0):
//  1. 读 /proc/net/{tcp,tcp6,udp,udp6} 找 local_address==src 的行 → socket inode;
//  2. 扫 /proc/<pid>/fd/* 的 symlink 找 "socket:[inode]" → 该 pid,readlink /proc/<pid>/exe 得路径。
//
// 仅对【本机进程经本机入站(socks/http/tun/redirect/tproxy)连入】有意义 —— 此时 src 就是发起
// 进程持有的本地端。查不到(非本机 / 已退出 / 权限不足)一律 ok=false,process 规则不命中。
type procFinder struct{}

var _ rule.ProcessFinder = procFinder{}

func NewProcessFinder() rule.ProcessFinder { return procFinder{} }

func (procFinder) FindProcess(network string, src netip.AddrPort) (name, path string, ok bool) {
	if !src.IsValid() {
		return "", "", false
	}
	var files []string
	switch network {
	case "tcp":
		files = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	case "udp":
		files = []string{"/proc/net/udp", "/proc/net/udp6"}
	default:
		return "", "", false
	}
	inode, ok := findSocketInode(files, src)
	if !ok {
		return "", "", false
	}
	exe, ok := exeByInode(inode)
	if !ok {
		return "", "", false
	}
	return filepath.Base(exe), exe, true
}

// findSocketInode 在 /proc/net/{tcp,udp}[6] 里找 local_address 匹配 src 的行,返回其 socket inode。
// 优先 ip+port 全匹配;src 只关心端口时(ip 未指定)退化按端口。
func findSocketInode(files []string, src netip.AddrPort) (string, bool) {
	wantPort := src.Port()
	wantIP := src.Addr().Unmap()
	var portOnly string // 仅端口命中的候选(次选)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for li, line := range lines {
			if li == 0 { // 表头
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			ip, port, ok := parseHexAddr(fields[1]) // local_address = "HEXIP:HEXPORT"
			if !ok || port != wantPort {
				continue
			}
			inode := fields[9]
			if wantIP.IsValid() && ip == wantIP {
				return inode, true // ip+port 全匹配,最优
			}
			if portOnly == "" {
				portOnly = inode
			}
		}
	}
	if portOnly != "" {
		return portOnly, true
	}
	return "", false
}

// parseHexAddr 解析 /proc/net/* 的 "local_address" 字段 "HEXIP:HEXPORT"。
// IP 是 native-endian(x86/arm 均小端)hex,port 是大端 hex。
func parseHexAddr(s string) (netip.Addr, uint16, bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return netip.Addr{}, 0, false
	}
	ip, ok := parseHexIP(s[:i])
	if !ok {
		return netip.Addr{}, 0, false
	}
	p, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	return ip, uint16(p), true
}

// parseHexIP 把 native-endian hex(v4=8 hex chars、v6=32)转 netip.Addr。
func parseHexIP(s string) (netip.Addr, bool) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return netip.Addr{}, false
	}
	switch len(b) {
	case 4: // 小端 32 位字 → 大端字节序
		return netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}), true
	case 16: // 4 个小端 32 位字,逐字反转
		var a [16]byte
		for i := 0; i < 16; i += 4 {
			a[i], a[i+1], a[i+2], a[i+3] = b[i+3], b[i+2], b[i+1], b[i]
		}
		return netip.AddrFrom16(a).Unmap(), true
	}
	return netip.Addr{}, false
}

// exeByInode 扫 /proc/<pid>/fd/* 找指向 "socket:[inode]" 的 fd,返回该 pid 的 /proc/<pid>/exe 目标。
func exeByInode(inode string) (string, bool) {
	want := "socket:[" + inode + "]"
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return "", false
	}
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid := p.Name()
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}
		fdDir := "/proc/" + pid + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // 权限不足 / 进程已退出
		}
		for _, fd := range fds {
			target, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			if target == want {
				exe, err := os.Readlink("/proc/" + pid + "/exe")
				if err != nil {
					return "", false
				}
				return exe, true
			}
		}
	}
	return "", false
}
