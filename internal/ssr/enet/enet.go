// Package enet 是 vendored SSR 代码对 mihomo common/net 的最小替身(以别名 N 导入)。
// SSR 的 vendored 代码只把它当作「增强型 PacketConn」接口用(WriteTo/ReadFrom + WaitReadFrom),
// 故这里只需给出该接口定义即可让全部 UDP 路径编译通过。TCP(StreamConn)路径不碰它。
package enet

import "net"

// EnhancePacketConn 是 mihomo 增强型 PacketConn:在标准 net.PacketConn 之上加一个零拷贝
// WaitReadFrom(返回底层缓冲 + 归还回调)。vendored SSR 的 packet.go 以此为嵌入接口。
type EnhancePacketConn interface {
	net.PacketConn
	WaitReadFrom() (data []byte, put func(), addr net.Addr, err error)
}
