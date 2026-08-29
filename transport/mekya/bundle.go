// Package mekya 自写实现 mekya 传输 —— KCP-over-HTTP(meek 式轮询隧道,mihomo 独有;xray/sing-box 无)。
// KCP 可靠层复用 NTR 自有 mkcpcore(与 mihomo transport/mkcp 线级互通,ix-mkcp 已双向验证);meek 的
// HTTP 轮询 + 会话多路复用 + 包捆绑格式自写、逐字节对齐 mihomo transport/mekya。是 BaseTransport(自拨
// HTTP+KCP,产可靠 link.Stream),惯用叠法 [mekya, vmess]。
//
// 线格式(禁改,承 mihomo transport/mekya):
//   - 请求/响应体 = 多个 KCP 包捆绑,每包 [2B BE 长度][KCP 包](见 writePacketBundle)。
//   - 客户端 POST 到 url,头 X-Session-ID: base64url(16B 随机会话号);响应体回带下行 KCP 包捆绑。
//   - KCP 包本身走 mkcpcore(参数须两端一致)。
//
// v1:单连接轮询(mihomo 客户端用连接池/写批处理是【性能优化】,非线格式;单连接与其服务端互通)。
package mekya

import (
	"encoding/binary"
	"io"
)

const packetBundleOverhead = 2

// writePacketBundle 写一个 KCP 包到捆绑流:[2B BE 长度][包]。
func writePacketBundle(w io.Writer, packet []byte) error {
	if len(packet) > 0xffff {
		return io.ErrShortBuffer
	}
	var header [packetBundleOverhead]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(packet)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(packet)
	return err
}

// readPacketBundle 从捆绑流读一个 KCP 包。EOF 表示捆绑结束。
func readPacketBundle(r io.Reader) ([]byte, error) {
	var header [packetBundleOverhead]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(header[:])
	packet := make([]byte, length)
	if _, err := io.ReadFull(r, packet); err != nil {
		return nil, err
	}
	return packet, nil
}
