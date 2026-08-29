package reality

import (
	"net"
	"reflect"
	"unsafe"

	singvless "github.com/metacubex/sing-vmess/vless"
	utls "github.com/refraction-networking/utls"
	xreality "github.com/xtls/reality"
)

// init 向 sing-vmess/vless 的 vision tlsRegistry 注册 REALITY 用的两种 TLS 连接类型,使
// VLESS Vision 能在 REALITY 之上工作(vless+vision+reality 是 Xray 的旗舰组合)。
//
// Vision 靠反射进 TLS 连接的 input(bytes.Reader)/rawInput(bytes.Buffer)字段按 TLS 记录边界
// 做 splice。sing-vmess 默认只注册 *crypto/tls.Conn;REALITY 客户端用 refraction-networking/utls
// 的 *UConn(内嵌 *Conn)、服务端用 xtls/reality 的 *Conn —— 两者都是 crypto/tls 的 fork,input/
// rawInput 字段同名同型,故反射可用。transport/reality 被 manifest blank-import 时此注册即生效。
func init() {
	singvless.RegisterTLS(func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		switch c := conn.(type) {
		case *utls.UConn: // REALITY 客户端:uTLS,反射进内嵌的 *utls.Conn
			return true, c.NetConn(), reflect.TypeOf(c.Conn).Elem(), unsafe.Pointer(c.Conn)
		case *xreality.Conn: // REALITY 服务端
			return true, c.NetConn(), reflect.TypeOf(c).Elem(), unsafe.Pointer(c)
		}
		return
	})
}
