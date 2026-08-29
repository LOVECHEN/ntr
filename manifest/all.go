// Package manifest 是唯一的装配触点(composition root):每加一个协议 = 这里加一行
// blank-import(承设计第 1 章 §1.6、第 2 章 §2.6)。核心对外只吹"加协议核心零 diff",
// 不吹"零编辑" —— 这一行 blank-import 是必需且唯一的编辑。
package manifest

import (
	_ "github.com/LOVECHEN/ntr/proto/gost"
	_ "github.com/LOVECHEN/ntr/proto/httpproxy"
	_ "github.com/LOVECHEN/ntr/proto/mixed"
	_ "github.com/LOVECHEN/ntr/proto/mtproto"
	_ "github.com/LOVECHEN/ntr/proto/shadowsocks"
	_ "github.com/LOVECHEN/ntr/proto/snell"
	_ "github.com/LOVECHEN/ntr/proto/socks"
	_ "github.com/LOVECHEN/ntr/proto/ssr"
	_ "github.com/LOVECHEN/ntr/proto/trojan"
	_ "github.com/LOVECHEN/ntr/proto/vless"
	_ "github.com/LOVECHEN/ntr/proto/vmess"
	_ "github.com/LOVECHEN/ntr/transport/grpc"
	_ "github.com/LOVECHEN/ntr/transport/h2"
	_ "github.com/LOVECHEN/ntr/transport/httpupgrade"
	_ "github.com/LOVECHEN/ntr/transport/jls"
	_ "github.com/LOVECHEN/ntr/transport/kcptun"
	_ "github.com/LOVECHEN/ntr/transport/mekya"
	_ "github.com/LOVECHEN/ntr/transport/mkcp"
	_ "github.com/LOVECHEN/ntr/transport/obfs"
	_ "github.com/LOVECHEN/ntr/transport/quic"
	_ "github.com/LOVECHEN/ntr/transport/reality"
	_ "github.com/LOVECHEN/ntr/transport/restls"
	_ "github.com/LOVECHEN/ntr/transport/shadowtls"
	_ "github.com/LOVECHEN/ntr/transport/tls"
	_ "github.com/LOVECHEN/ntr/transport/tlsmirror"
	_ "github.com/LOVECHEN/ntr/transport/vlessenc"
	_ "github.com/LOVECHEN/ntr/transport/ws"
	_ "github.com/LOVECHEN/ntr/transport/xhttp"
)
