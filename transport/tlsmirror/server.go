package tlsmirror

import (
	"context"
	"net"
)

// ServeConnReady 在 carrierConn(客户端 TCP)与 forwardConn(到真后端的 TCP)之间起透明镜像,阻塞到隐蔽
// 通道被【激活】(收到客户端第一条隐蔽记录)再返回隐蔽 Conn。非隧道探测连接不会激活 → 一直被透明中继到
// 真后端(诱骗),ServeConnReady 直到其关闭/超时才返回错误。
func ServeConnReady(ctx context.Context, carrierConn net.Conn, forwardConn net.Conn, cfg ServerConfig) (*Conn, error) {
	key, err := DecodePrimaryKey(cfg.PrimaryKey)
	if err != nil {
		_ = carrierConn.Close()
		_ = forwardConn.Close()
		return nil, err
	}

	ready := make(chan *Conn, 1)
	var hidden *Conn
	var activated bool
	mirror := newMirrorConn(ctx, carrierConn, forwardConn, cfg.ExplicitNonceCipherSuites,
		func(rec *record) (bool, error) {
			drop, err := hidden.handleInboundRecord(rec)
			if drop && !activated {
				activated = true
				select {
				case ready <- hidden:
				default:
				}
			}
			return drop, err
		},
		nil,
		nil,
		nil,
	)
	hidden = newHiddenConn(ctx, mirror, key, true, features{padding: cfg.Padding, watermark: cfg.Watermark})
	mirror.onS2CMessageTx = hidden.handleOutboundRecordTx
	mirror.start()

	select {
	case h := <-ready:
		return h, nil
	case <-mirror.ctx.Done():
		return nil, mirror.ctx.Err()
	case <-ctx.Done():
		_ = mirror.Close()
		return nil, ctx.Err()
	}
}
