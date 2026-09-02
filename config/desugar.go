package config

import (
	"fmt"
	"sort"

	"github.com/LOVECHEN/ntr/core/principal"
)

// Desugar 把配置糖(顶层 users:on/off/all + 平铺 keys)脱糖成运行时装配单元 []CredBinding
// (承第4章 §4.5.2;on 语义按 owner 调整为默认全开)。纯函数:不认识协议、不碰栈装配、无 I/O、
// 输出确定(允许口按名排序)。
//
//   - inboundNames: 所有已声明口名(校验 on/off 引用)。
//   - stackProtos:  口名 → 该口栈所需 per-user 认证协议(按栈序,外→内)。由口的栈决定(§4.4 规则3),
//     调用方(Build 期,有栈信息)传入;无认证口(mixed/tun)不在表或空 → 不产 per-user binding。
//   - canon:        (proto, secret) → canonical 鉴权键(= 该协议 CredentialCodec.AuthKey)。装配期注入;
//     测试可传 identity。
//
// 允许口集:全开(缺省 on 或 on:all)= 所有口;白名单(on:[口])= 列出的口;再由 off 黑名单挖除。
// 缺密钥:全开下某口缺栈所需密钥 = 该用户没买这口,静默跳过;显式 on 了却缺 → E-KEY-MISSING。
// 轮换:某层多把 key → 该层产多个平行 binding(多层则笛卡尔积),共享同一 BillID。
func Desugar(
	users []User,
	inboundNames map[string]bool,
	stackProtos map[string][]string,
	canon func(proto, secret string) ([]byte, error),
) ([]principal.CredBinding, error) {
	seen := make(map[string]bool, len(users))
	var out []principal.CredBinding

	for _, u := range users {
		if u.Name == "" {
			return nil, fmt.Errorf("config: 存在缺 name 的 user 块")
		}
		if seen[u.Name] {
			return nil, fmt.Errorf("config: user 重名 %q (E-USER-DUP)", u.Name)
		}
		seen[u.Name] = true

		for _, ib := range u.On {
			if ib != OnAll && !inboundNames[ib] {
				return nil, fmt.Errorf("config: user %q 的 on 引用未知口 %q (E-INBOUND-UNKNOWN)", u.Name, ib)
			}
		}
		for _, ib := range u.Off {
			if !inboundNames[ib] {
				return nil, fmt.Errorf("config: user %q 的 off 引用未知口 %q (E-INBOUND-UNKNOWN)", u.Name, ib)
			}
		}

		limit, err := buildLimitRef(u)
		if err != nil {
			return nil, err
		}
		allowed := allowedInbounds(u, inboundNames)
		explicitOn := !u.AllowsAllInbounds()

		for _, ib := range sortedKeys(allowed) {
			protos := stackProtos[ib]
			if len(protos) == 0 {
				continue // 无认证口:不产 per-user binding(其流量归 Ambient/Unmatched)
			}
			layerVals := make([][]string, len(protos))
			missing := ""
			for i, p := range protos {
				ks, ok := u.Keys[p]
				if !ok || len(ks.Values) == 0 {
					missing = p
					break
				}
				layerVals[i] = ks.Values
			}
			if missing != "" {
				if explicitOn && sliceContains(u.On, ib) {
					return nil, fmt.Errorf("config: user %q on 了口 %q 但缺该口栈所需协议 %q 的密钥 (E-KEY-MISSING)", u.Name, ib, missing)
				}
				continue // 全开下缺密钥 = 没买这口,跳过
			}
			bindings, err := expandLayers(u, ib, protos, layerVals, limit, canon)
			if err != nil {
				return nil, err
			}
			out = append(out, bindings...)
		}
	}
	return out, nil
}

// allowedInbounds 算该 user 的允许口集:全开=所有口;白名单=on 列出的;再减 off。
func allowedInbounds(u User, all map[string]bool) map[string]bool {
	allowed := make(map[string]bool)
	if u.AllowsAllInbounds() {
		for ib := range all {
			allowed[ib] = true
		}
	} else {
		for _, ib := range u.On {
			if ib != OnAll {
				allowed[ib] = true
			}
		}
	}
	for _, ib := range u.Off {
		delete(allowed, ib)
	}
	return allowed
}

// buildLimitRef:设了 rate/max-conns/max-ips 任一 → 建一个 LimitRef(该 user 全部 binding 共指);否则 nil。
func buildLimitRef(u User) (*principal.LimitRef, error) {
	if u.Rate == "" && u.MaxConns == 0 && u.MaxIPs == 0 {
		return nil, nil
	}
	var rate uint64
	if u.Rate != "" {
		r, err := parseRate(u.Rate)
		if err != nil {
			return nil, fmt.Errorf("config: user %q rate %q: %w", u.Name, u.Rate, err)
		}
		rate = uint64(r)
	}
	ipx := principal.IPReject
	if u.OnExceedIPs == "evict-oldest" {
		ipx = principal.IPEvictOldest
	}
	return &principal.LimitRef{Rate: rate, MaxConns: u.MaxConns, MaxIPs: u.MaxIPs, OnExceedIPs: ipx}, nil
}

// expandLayers 产一个口的 binding:多层 × 轮换 = 笛卡尔积(每层选一把 key),共享同一 BillID。
func expandLayers(u User, ib string, protos []string, layerVals [][]string, limit *principal.LimitRef, canon func(string, string) ([]byte, error)) ([]principal.CredBinding, error) {
	combos := [][]string{{}}
	for i := range protos {
		var next [][]string
		for _, c := range combos {
			for _, v := range layerVals[i] {
				nc := make([]string, len(c)+1)
				copy(nc, c)
				nc[len(c)] = v
				next = append(next, nc)
			}
		}
		combos = next
	}
	bill := principal.BillIDOf(u.Name, ib)
	out := make([]principal.CredBinding, 0, len(combos))
	for _, combo := range combos {
		layers := make([]principal.AuthLayer, len(protos))
		for i, p := range protos {
			key, err := canon(p, combo[i])
			if err != nil {
				return nil, fmt.Errorf("config: user %q 口 %q 层 %q 密钥规范化失败: %w", u.Name, ib, p, err)
			}
			layers[i] = principal.AuthLayer{Scheme: p, Key: key}
		}
		out = append(out, principal.CredBinding{
			Inbound: ib,
			Layers:  layers,
			BillID:  bill,
			Name:    u.Name,
			Limit:   limit,
			Origin:  principal.OriginConfig,
		})
	}
	return out, nil
}

func sortedKeys(m map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
