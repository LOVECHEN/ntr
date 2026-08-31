//go:build with_tun && linux

package tun

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// autoRoute 把默认流量自动导入 tun:split-default(0.0.0.0/1 + 128.0.0.0/1 两条覆盖【全部】出站
// 目标,但【不动】系统 default 路由,故可无损叠加/撤销),并把 excludes(通常=每个 proxy 出站的
// 服务器 IP)经【原默认网关】直连。返回清理函数(逆序撤销所有新增路由)。
//
// ★footgun:这是 TUN 全局网关的自动路由,配错会断网。仅 Linux;需 CAP_NET_ADMIN + iproute2。
// ★排除代理服务器 IP 是【必须】:出站经代理时,若代理服务器地址本身也被 0/1 捕获进 tun,则「拨向
//   代理」的连接又被 netstack 抓走 → 无限回环、彻底不通。故 auto-route 场景务必把每个 proxy 出站
//   的 server IP 列入 route-exclude(direct 出站因目标即真实地址、无固定跳板,当前不自动排除)。
func autoRoute(ifName string, excludes []string) (func(), error) {
	if _, err := exec.LookPath("ip"); err != nil {
		return nil, fmt.Errorf("auto-route 需要 iproute2(ip 命令):%w", err)
	}
	gw, dev, err := defaultGateway()
	if err != nil {
		return nil, fmt.Errorf("定位原默认网关失败(auto-route 需据此排除代理服务器):%w", err)
	}
	var undo [][]string // 已加路由的撤销命令,逆序执行
	rollback := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			_ = exec.Command("ip", undo[i]...).Run()
		}
	}
	add := func(delArgs []string, addArgs ...string) error {
		if out, e := exec.Command("ip", addArgs...).CombinedOutput(); e != nil {
			return fmt.Errorf("ip %s:%v(%s)", strings.Join(addArgs, " "), e, strings.TrimSpace(string(out)))
		}
		undo = append(undo, delArgs)
		return nil
	}
	// ① 排除:代理服务器 IP 经原网关直连(防回环)
	for _, ip := range excludes {
		host := ip
		if !strings.Contains(host, "/") {
			host += "/32"
		}
		if err := add([]string{"route", "del", host}, "route", "add", host, "via", gw, "dev", dev); err != nil {
			rollback()
			return nil, err
		}
	}
	// ② split-default:其余全部流量进 tun(不动系统 default)
	for _, r := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := add([]string{"route", "del", r, "dev", ifName}, "route", "add", r, "dev", ifName); err != nil {
			rollback()
			return nil, err
		}
	}
	return rollback, nil
}

// defaultGateway 读 /proc/net/route 取 IPv4 默认路由(Destination=00000000)的网关 IP + 接口名。
func defaultGateway() (gw, dev string, err error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // 跳表头
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[1] != "00000000" { // 非 default
			continue
		}
		g, e := hexLEtoIP(fields[2])
		if e != nil {
			continue
		}
		return g, fields[0], nil
	}
	return "", "", fmt.Errorf("未找到 IPv4 默认路由")
}

// hexLEtoIP 把 /proc/net/route 的小端 hex(如 0102A8C0 → 192.168.2.1)转点分 IP。
func hexLEtoIP(h string) (string, error) {
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return "", err
	}
	return netip.AddrFrom4([4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}).String(), nil
}
