package ssr

import (
	"net"

	"github.com/LOVECHEN/ntr/internal/ssr/obfs"
	"github.com/LOVECHEN/ntr/internal/ssr/protocol"
)

// serverObfsPlugin 建非 plain 的服务端 obfs 逆向(http_simple/http_post/random_head/tls1.2_ticket_auth)。
func serverObfsPlugin(name string, below net.Conn, key []byte, ivSize int, host string, port int, param string) (net.Conn, int, error) {
	c, err := obfs.PickServerObfs(name, below, key)
	if err != nil {
		return nil, 0, err
	}
	return c, 0, nil
}

// serverProtocolPlugin 建非 origin 的服务端 protocol 逆向。当前支持 auth_aes128_sha1 / auth_aes128_md5。
func serverProtocolPlugin(name string, c net.Conn, iv, key []byte, overhead int, param string) (net.Conn, error) {
	return protocol.PickServerProtocol(name, c, iv, key, overhead, param)
}
