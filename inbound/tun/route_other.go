//go:build with_tun && !linux

package tun

import "errors"

// autoRoute 目前仅 Linux 实现(darwin/其他平台的 split-default + 排除需各自的路由 API,后续增量)。
func autoRoute(_ string, _ []string) (func(), error) {
	return nil, errors.New("auto-route 目前仅 Linux 支持")
}
