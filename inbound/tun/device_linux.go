//go:build with_tun && linux

package tun

import (
	"fmt"
	"net/netip"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/LOVECHEN/ntr/buf"
	"github.com/LOVECHEN/ntr/core/link"
)

// linuxDevice 是 Linux TUN 设备(/dev/net/tun + IFF_TUN|IFF_NO_PI):收发【裸 IP 包】(无 PI 头、无偏移),
// 天然对齐 core/link.Device 的单包语义 —— 最干净的驱动层,不引 wireguard-go 那套带 virtio 偏移的批量 API。
type linuxDevice struct {
	f    *os.File
	name string
	mtu  uint32
}

// openDevice 打开/创建名为 name 的 TUN 接口,按 addr(可空)配地址 + 置 MTU + up。返回 link.Device。
func openDevice(name string, mtu uint32, addr netip.Prefix) (link.Device, error) {
	if mtu == 0 {
		mtu = 1500
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun:%w", err)
	}
	var ifr ifreqFlags
	copy(ifr.name[:], name)
	ifr.flags = unix.IFF_TUN | unix.IFF_NO_PI
	if err := ioctl(uintptr(fd), unix.TUNSETIFF, unsafe.Pointer(&ifr)); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: TUNSETIFF:%w", err)
	}
	real := trimName(ifr.name[:])
	d := &linuxDevice{f: os.NewFile(uintptr(fd), "tun"), name: real, mtu: mtu}
	if err := d.configure(addr); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// configure 用 AF_INET 控制 socket 上的 ioctl 设 MTU / 地址 / netmask,并 up 接口。
func (d *linuxDevice) configure(addr netip.Prefix) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("tun: 控制 socket:%w", err)
	}
	defer unix.Close(s)

	// MTU
	var mtuReq ifreqInt
	copy(mtuReq.name[:], d.name)
	mtuReq.val = int32(d.mtu)
	if err := ioctl(uintptr(s), unix.SIOCSIFMTU, unsafe.Pointer(&mtuReq)); err != nil {
		return fmt.Errorf("tun: SIOCSIFMTU:%w", err)
	}

	// 地址 + 掩码(仅 IPv4;IPv6 需 rtnetlink,后续增量)
	if addr.IsValid() && addr.Addr().Is4() {
		var ar ifreqAddr
		copy(ar.name[:], d.name)
		ar.addr = sockaddrIn4(addr.Addr())
		if err := ioctl(uintptr(s), unix.SIOCSIFADDR, unsafe.Pointer(&ar)); err != nil {
			return fmt.Errorf("tun: SIOCSIFADDR:%w", err)
		}
		mask := netip.PrefixFrom(maskAddr(addr.Bits()), 32).Addr()
		var mr ifreqAddr
		copy(mr.name[:], d.name)
		mr.addr = sockaddrIn4(mask)
		if err := ioctl(uintptr(s), unix.SIOCSIFNETMASK, unsafe.Pointer(&mr)); err != nil {
			return fmt.Errorf("tun: SIOCSIFNETMASK:%w", err)
		}
	}

	// up + running
	var fr ifreqInt
	copy(fr.name[:], d.name)
	if err := ioctl(uintptr(s), unix.SIOCGIFFLAGS, unsafe.Pointer(&fr)); err != nil {
		return fmt.Errorf("tun: SIOCGIFFLAGS:%w", err)
	}
	fr.val |= int32(uint16(unix.IFF_UP | unix.IFF_RUNNING))
	if err := ioctl(uintptr(s), unix.SIOCSIFFLAGS, unsafe.Pointer(&fr)); err != nil {
		return fmt.Errorf("tun: SIOCSIFFLAGS(up):%w", err)
	}
	return nil
}

func (d *linuxDevice) ReadPacket(b *buf.Buffer) error {
	n, err := d.f.Read(b.ExtendTail(int(d.mtu) + 4))
	if err != nil {
		return err
	}
	b.Truncate(n)
	return nil
}

func (d *linuxDevice) WritePacket(b *buf.Buffer) error {
	_, err := d.f.Write(b.Bytes())
	return err
}

func (d *linuxDevice) MTU() uint32 { return d.mtu }
func (d *linuxDevice) Close() error { return d.f.Close() }

func deviceName(cfgName string) string {
	if cfgName != "" {
		return cfgName
	}
	return "ntr-tun0"
}

// ── ioctl / ifreq 辅助 ──

func ioctl(fd, req uintptr, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, req, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

type ifreqFlags struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}
type ifreqInt struct {
	name [16]byte
	val  int32
	_    [20]byte
}
type ifreqAddr struct {
	name [16]byte
	addr unix.RawSockaddrInet4
	_    [8]byte
}

func sockaddrIn4(a netip.Addr) unix.RawSockaddrInet4 {
	var s unix.RawSockaddrInet4
	s.Family = unix.AF_INET
	s.Addr = a.As4()
	return s
}

func maskAddr(bits int) netip.Addr {
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
	return netip.AddrFrom4(m)
}

func trimName(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
