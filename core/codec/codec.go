// Package codec 定义纯函数线协议 codec 框架(承设计第 3 章 §3.4)。
//
// 每个线协议实现 FrameCodec[F]:Encode/Decode 只碰 *buf.Buffer,不持 net.Conn、
// 不起 goroutine、确定性。持连接调 codec 的 impure wrapper 在协议包的 node.go,
// 与 codec 分文件、分测试。对拷一致性 harness 在子包 codectest。
package codec

import "github.com/LOVECHEN/ntr/buf"

// FrameCodec 是一帧的纯编解码器。F 是协议自有的帧结构。
type FrameCodec[F any] interface {
	// Encode 把一帧写进 dst 的载荷区(可借 headroom/tailroom)。
	Encode(dst *buf.Buffer, f F) error
	// Decode 从 src 解一帧(消费 src 的载荷)。
	Decode(src *buf.Buffer) (F, error)
}

// Command 是命令字节,取代魔法串(如 "v1.rvs.cool")。
type Command uint8

const (
	CmdTCP     Command = 0x01
	CmdUDP     Command = 0x02
	CmdMux     Command = 0x03
	CmdReverse Command = 0x04
)
