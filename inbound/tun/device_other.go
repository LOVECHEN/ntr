//go:build with_tun && !linux && !darwin

package tun

import (
	"errors"
	"net/netip"

	"github.com/LOVECHEN/ntr/core/link"
)

// 其他平台暂无 TUN 设备实现(linux/darwin 已支持)。
func openDevice(_ string, _ uint32, _ netip.Prefix) (link.Device, error) {
	return nil, errors.New("tun: 当前平台暂不支持 TUN(仅 linux / darwin)")
}

func deviceName(cfgName string) string { return cfgName }
