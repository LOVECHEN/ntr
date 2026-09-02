package config

import (
	"fmt"
	"sort"

	"github.com/LOVECHEN/ntr/core/principal"
)

// Desugar 把配置糖(顶层 users:on/off/all + 平铺 keys)脱糖成运行时装配单元 []CredBinding
// (承第4章 §4.5.2;on 语义按 owner 调整为默认全开)。纯函数:不认识协议、不碰栈装配、无 I/O、
// 输出确定(允许口按名排序)。产出的 AuthLayer.Key 是【原始 secret 字节】,canonical 派生
// (CredentialCodec.AuthKey)留给装配期 —— 那时才拿得到协议实例。
//
//   - inboundNames: 所有已声明口名(校验 on/off 引用)。
//   - stackProtos:  口名 → 该口栈所需 per-user 认证协议(按栈序,外→内)。由口的栈决定(§4.4 规则3),
//     调用方(Build 期,有栈信息)传入;无认证口(mixed/tun)不在表或空 → 不产 per-user binding。
//
// 允许口集:全开(缺省 on 或 on:all)= 所有口;白名单(on:[口])= 列出的口;再由 off 黑名单挖除。
// 缺密钥:全开下某口缺栈所需密钥 = 该用户没买这口,静默跳过;显式 on 了却缺 → E-KEY-MISSING。
// 轮换:某层多把 key → 该层产多个平行 binding(多层则笛卡尔积),共享同一 BillID。
func Desugar(users []User, inboundNames map[string]bool, stackProtos map[string][]string) ([]principal.CredBinding, error) {
	seen := make(map[string]bool, len(users))
	// keyOwner:(口, 协议, 原始密钥) → 已占用它的 user。同口同协议同 key 被两个人用 = 鉴权歧义 + 计费串号,
	// 装配期 auth.Add 会静默覆盖(那语义是给 reload 换密的),所以必须在这里判死(E-KEY-DUP)。
	keyOwner := make(map[string]string)
	var out []principal.CredBinding

	for _, u := range users {
		if u.Name == "" {
			return nil, fmt.Errorf("config: 存在缺 name 的 user 块")
		}
		if seen[u.Name] {
			return nil, fmt.Errorf("config: user 重名 %q (E-USER-DUP)", u.Name)
		}
		seen[u.Name] = true

		hasAll := false
		for _, ib := range u.On {
			if ib == OnAll {
				hasAll = true
				continue
			}
			if !inboundNames[ib] {
				return nil, fmt.Errorf("config: user %q 的 on 引用未知口 %q (E-INBOUND-UNKNOWN)", u.Name, ib)
			}
		}
		if hasAll && len(u.On) > 1 { // all 已全开,再列具名口会让"显式 on 缺密钥报错"的意图失效 → 判死,不留歧义
			return nil, fmt.Errorf("config: user %q 的 on 含保留字 all 时不能再列具名口(all 即全开;要收窄就去掉 all)", u.Name)
		}
		for _, ib := range u.Off {
			if ib == OnAll {
				return nil, fmt.Errorf("config: user %q 的 off 不支持保留字 all(要全屏蔽请把该 user 删掉或逐口列出)", u.Name)
			}
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
			for i, p := range protos {
				for _, v := range layerVals[i] {
					k := ib + "\x00" + p + "\x00" + v
					if owner, dup := keyOwner[k]; dup && owner != u.Name {
						return nil, fmt.Errorf("config: user %q 与 %q 在口 %q 的协议 %q 上用了同一把密钥 (E-KEY-DUP):鉴权无法区分、计费会串号", u.Name, owner, ib, p)
					}
					keyOwner[k] = u.Name
				}
			}
			out = append(out, expandLayers(u, ib, protos, layerVals, limit)...)
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
// on-exceed-ips 当前只实现 reject:写了别的值报错而不是静默吞掉(冻结律#6 绝不静默)。
func buildLimitRef(u User) (*principal.LimitRef, error) {
	switch u.OnExceedIPs {
	case "", "reject":
	default:
		return nil, fmt.Errorf("config: user %q on-exceed-ips %q 未实现(当前仅 reject)", u.Name, u.OnExceedIPs)
	}
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
	return &principal.LimitRef{Rate: rate, MaxConns: u.MaxConns, MaxIPs: u.MaxIPs}, nil
}

// expandLayers 产一个口的 binding:多层 × 轮换 = 笛卡尔积(每层选一把 key),共享同一 BillID。
// Key 放原始 secret 字节,装配期再经协议 CredentialCodec.AuthKey 派生。
func expandLayers(u User, ib string, protos []string, layerVals [][]string, limit *principal.LimitRef) []principal.CredBinding {
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
			layers[i] = principal.AuthLayer{Scheme: p, Key: []byte(combo[i])}
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
	return out
}

// sortedKeysAny 报 map 的键(排序),供报错信息稳定可读。
func sortedKeysAny(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
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
