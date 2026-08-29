//go:build with_tun && darwin

package tun

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

// darwinDevice 是 macOS utun 设备。utun 每个包带 4 字节 AF 协议族前缀(AF_INET=2 / AF_INET6=30,
// 主机序),读时剥、写时补 —— 这层前缀是 utun 的线上格式,对齐到 core/link.Device 的裸 IP 语义。
// 地址/up 用 ifconfig 配(macOS 惯用;TUN 本就需特权)。
type darwinDevice struct {
	f    *os.File
	name string
	mtu  uint32
}

// openDevice 打开一个 utun(name 形如 utunN;空则由内核分配),配地址 + up。
func openDevice(name string, mtu uint32, addr netip.Prefix) (link.Device, error) {
	if mtu == 0 {
		mtu = 1500
	}
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2 /*SYSPROTO_CONTROL*/)
	if err != nil {
		return nil, fmt.Errorf("tun: AF_SYSTEM socket:%w", err)
	}
	// 取 utun 控制 id。
	var ctlInfo unix.CtlInfo
	copy(ctlInfo.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, &ctlInfo); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: CTLIOCGINFO:%w", err)
	}
	unit := utunUnit(name) // utunN → N+1;空 → 0(内核自选)
	sc := unix.SockaddrCtl{ID: ctlInfo.Id, Unit: uint32(unit)}
	if err := unix.Connect(fd, &sc); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: connect utun(需 root):%w", err)
	}
	real, err := utunName(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	_ = unix.SetNonblock(fd, false)
	d := &darwinDevice{f: os.NewFile(uintptr(fd), "utun"), name: real, mtu: mtu}
	if err := d.configure(addr); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// configure 用 ifconfig 设 MTU / 地址 / up(macOS 惯用做法)。
func (d *darwinDevice) configure(addr netip.Prefix) error {
	run := func(args ...string) error {
		if out, err := exec.Command("ifconfig", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("tun: ifconfig %v:%w(%s)", args, err, string(out))
		}
		return nil
	}
	if err := run(d.name, "mtu", fmt.Sprint(d.mtu)); err != nil {
		return err
	}
	if addr.IsValid() && addr.Addr().Is4() {
		// point-to-point:本端 = 对端 = 网卡地址(TUN 惯用)
		if err := run(d.name, "inet", addr.Addr().String(), addr.Addr().String(), "netmask", maskDotted(addr.Bits())); err != nil {
			return err
		}
	} else if addr.IsValid() {
		if err := run(d.name, "inet6", addr.String()); err != nil {
			return err
		}
	}
	return run(d.name, "up")
}

const afPrefixLen = 4

func (d *darwinDevice) ReadPacket(b *buf.Buffer) error {
	raw := make([]byte, int(d.mtu)+afPrefixLen)
	n, err := d.f.Read(raw)
	if err != nil {
		return err
	}
	if n <= afPrefixLen {
		b.Reset()
		return nil
	}
	_, _ = b.Write(raw[afPrefixLen:n]) // 剥 4 字节 AF 前缀
	return nil
}

func (d *darwinDevice) WritePacket(b *buf.Buffer) error {
	data := b.Bytes()
	af := byte(unix.AF_INET)
	if len(data) > 0 && data[0]>>4 == 6 {
		af = byte(unix.AF_INET6)
	}
	pkt := make([]byte, afPrefixLen+len(data))
	pkt[3] = af // 主机序 4 字节:0,0,0,AF
	copy(pkt[afPrefixLen:], data)
	_, err := d.f.Write(pkt)
	return err
}

func (d *darwinDevice) MTU() uint32  { return d.mtu }
func (d *darwinDevice) Close() error { return d.f.Close() }

func deviceName(cfgName string) string { return cfgName } // 空 → 内核自选 utunN

// utunUnit:utunN → N+1(sc_unit 从 1 起);其余/空 → 0(内核自选)。
func utunUnit(name string) int {
	var n int
	if _, err := fmt.Sscanf(name, "utun%d", &n); err == nil {
		return n + 1
	}
	return 0
}

// utunName 取内核分配的接口名(getsockopt UTUN_OPT_IFNAME=2)。
func utunName(fd int) (string, error) {
	name, err := unix.GetsockoptString(fd, 2 /*SYSPROTO_CONTROL*/, 2 /*UTUN_OPT_IFNAME*/)
	if err != nil {
		return "", fmt.Errorf("tun: 取 utun 名:%w", err)
	}
	return name, nil
}

func maskDotted(bits int) string {
	var m [4]byte
	for i := 0; i < 4; i++ {
		if bits >= 8 {
			m[i] = 0xff
			bits -= 8
		} else if bits > 0 {
			m[i] = byte(0xff << (8 - bits))
			bits = 0
		}
	}
	return netip.AddrFrom4(m).String()
}

var _ = unsafe.Pointer(nil)
