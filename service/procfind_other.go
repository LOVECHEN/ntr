//go:build !linux

package service

import (
	"net/netip"

	"github.com/LOVECHEN/ntr/rule"
)

// 非 Linux:进程反查未实现(macOS 需 libproc/CGO,与瘦核心 CGO=0 相斥;后续可加 x/sys)。
// 返回 ok=false → process 规则一律不命中,其余维度照常路由(优雅降级,不报错)。
type procFinder struct{}

var _ rule.ProcessFinder = procFinder{}

func NewProcessFinder() rule.ProcessFinder { return procFinder{} }

func (procFinder) FindProcess(string, netip.AddrPort) (name, path string, ok bool) {
	return "", "", false
}
