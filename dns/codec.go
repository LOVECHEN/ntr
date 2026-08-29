package dns

import (
	"encoding/binary"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// qkey 是缓存键:小写域名 + 查询类型(承 §10.1 cache 分片键)。
type qkey struct {
	name  string
	qtype dnsmessage.Type
}

// parseQuery 解出报文的 txid + 首个问题(name 小写、type)。用 x/net/dnsmessage —— 它安全处理
// 压缩指针(有界跳数、不 panic),满足设计对压缩环 DoS 的要求。ok=false 表示无法解析(交调用方裸转发)。
func parseQuery(raw []byte) (key qkey, id uint16, ok bool) {
	if len(raw) < 12 {
		return qkey{}, 0, false
	}
	id = binary.BigEndian.Uint16(raw[0:2])
	var p dnsmessage.Parser
	if _, err := p.Start(raw); err != nil {
		return qkey{}, id, false
	}
	q, err := p.Question()
	if err != nil {
		return qkey{}, id, false
	}
	return qkey{name: strings.ToLower(q.Name.String()), qtype: q.Type}, id, true
}

// minTTL 取应答里最小的 TTL(秒);无应答或解析失败返回 (0,false)(不缓存)。
func minTTL(raw []byte) (uint32, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(raw); err != nil {
		return 0, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return 0, false
	}
	min := uint32(0)
	have := false
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break // ErrSectionDone 等
		}
		if !have || h.TTL < min {
			min, have = h.TTL, true
		}
		if err := p.SkipAnswer(); err != nil {
			break
		}
	}
	return min, have
}

// setTxID 就地改写报文事务 ID(缓存命中时对齐新查询的 ID —— DNS 应答须回显查询 ID)。
func setTxID(raw []byte, id uint16) {
	if len(raw) >= 2 {
		binary.BigEndian.PutUint16(raw[0:2], id)
	}
}

// parseAddrs 从应答里取 A/AAAA 地址(供 Lookup 用)。
func parseAddrs(raw []byte) ([]netAddr, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(raw); err != nil {
		return nil, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, false
	}
	var out []netAddr
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return out, len(out) > 0
			}
			out = append(out, netAddr{v4: true, a4: r.A})
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return out, len(out) > 0
			}
			out = append(out, netAddr{a16: r.AAAA})
		default:
			if err := p.SkipAnswer(); err != nil {
				return out, len(out) > 0
			}
		}
	}
	return out, len(out) > 0
}

// netAddr 是解出的一条 A/AAAA(避免在 codec 里 import netip,转换留给 resolver)。
type netAddr struct {
	v4  bool
	a4  [4]byte
	a16 [16]byte
}
