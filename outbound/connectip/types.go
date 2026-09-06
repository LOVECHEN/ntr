package connectip

import (
	"context"
	"io"
	"net"
)

// User 是 CONNECT-IP 服务端用户(可选 HTTP Basic 保护;为空则不鉴权)。CONNECT-IP 本身(RFC 9484)
// 无认证层 —— 这里的 Basic 是 NTR 的可选扩展(客户端在 Extended CONNECT 请求带 Proxy-Authorization);
// 不配用户则保持开放隧道,与 Cloudflare 等无认证客户端互通。
type User struct {
	Name     string
	Password string
}

// MeterHook 在隧道建立(认证通过、流已接管)时按【认证用户】申请接入:连接闸 + max-ips + 计量登记。
// 与流式/其它会话式协议不同,CONNECT-IP 是一条长隧道搬任意 IP 包(非按目标建流),故不走 SessionDispatch,
// 而在此按【整条隧道】记账 —— 返回上/下行字节记账回调 + release(调用方 defer)。closer 交接入器用于
// Disable/KillIP 时强杀本隧道。user 为空 = 未鉴权(计量落 Ambient)。ok=false = 接入被拒(闸满/内存档),
// 调用方应关流。hook 为 nil = 不计量不设闸(纯开放隧道)。
type MeterHook func(ctx context.Context, user string, src net.Addr, closer io.Closer) (addUp, addDown func(int), release func(), ok bool)
