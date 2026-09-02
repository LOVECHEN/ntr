// Package config 是配置层:把 YAML 解码填充成哑的 spec.Node 层树,再交给 service 装配
// (承设计第 4 章:Decode 阶段哑、无逻辑;真正的 YAML 解码在此)。
//
// 它对协议/传输零特判 —— 层的 type 即注册表名,层内键原样转成 spec.Node 交插件自解析。
// 通用约定:任何 `xxx-file` 键会被读文件、以 `xxx` 键注入文件内容(证书/私钥等)。
package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/principal"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/route"
	"github.com/LOVECHEN/ntr/core/spec"
	"github.com/LOVECHEN/ntr/core/transport"
	"github.com/LOVECHEN/ntr/dns"
	"github.com/LOVECHEN/ntr/geo"
	dnsin "github.com/LOVECHEN/ntr/inbound/dns"
	"github.com/LOVECHEN/ntr/inbound/transparent"
	"github.com/LOVECHEN/ntr/inbound/tun"
	"github.com/LOVECHEN/ntr/inbound/tunnel"
	"github.com/LOVECHEN/ntr/meter"
	"github.com/LOVECHEN/ntr/outbound/anytls"
	"github.com/LOVECHEN/ntr/outbound/block"
	"github.com/LOVECHEN/ntr/outbound/connectip"
	"github.com/LOVECHEN/ntr/outbound/direct"
	dnsout "github.com/LOVECHEN/ntr/outbound/dns"
	"github.com/LOVECHEN/ntr/outbound/group"
	"github.com/LOVECHEN/ntr/outbound/hysteria1"
	"github.com/LOVECHEN/ntr/outbound/hysteria2"
	"github.com/LOVECHEN/ntr/outbound/masque"
	"github.com/LOVECHEN/ntr/outbound/mieru"
	"github.com/LOVECHEN/ntr/outbound/mux"
	muxcool "github.com/LOVECHEN/ntr/outbound/muxcool"
	"github.com/LOVECHEN/ntr/outbound/naive"
	"github.com/LOVECHEN/ntr/outbound/shadowquic"
	sshproto "github.com/LOVECHEN/ntr/outbound/ssh"
	"github.com/LOVECHEN/ntr/outbound/trusttunnel"
	"github.com/LOVECHEN/ntr/outbound/tuic"
	"github.com/LOVECHEN/ntr/outbound/upstream"
	"github.com/LOVECHEN/ntr/outbound/wireguard"
	"github.com/LOVECHEN/ntr/reverse"
	"github.com/LOVECHEN/ntr/rule"
	"github.com/LOVECHEN/ntr/ruleset"
	"github.com/LOVECHEN/ntr/service"
)

// File 是配置根。
type File struct {
	Inbounds  []Inbound    `yaml:"inbounds"`
	Outbounds []Outbound   `yaml:"outbounds"`
	Bridges   []Bridge     `yaml:"bridges"` // 反向代理:主动拨 Portal 建反连隧道(内网侧)
	DNS       *DNSSpec     `yaml:"dns"`     // DNS 解析子系统(承设计 §10.1;内置 dns 出站 + 未来 admission)
	Metrics   *MetricsSpec `yaml:"metrics"` // 计量与可观测(承设计 §5;按用户流量 + 连接数,HTTP 快照)
	Limits    *LimitsSpec  `yaml:"limits"`  // 全局限制(承设计 §6.2 层1:护机器 fd/带宽)
	Routing   *RoutingSpec `yaml:"routing"` // 规则分流引擎(承设计 §8.3;按目标域名/IP/端口选出站,首个命中)
	Users     []User       `yaml:"users"`   // 顶层用户集中式(第4章):权限白名单 on + keys 按协议/口;Desugar 脱糖成 CredBinding。空=无按人认证(纯面板模式凭据全走 API)

	// Reg 是运行时注入的计量注册表(非 YAML)。热重载:调用方设它以跨代复用同一 Registry;Build 会写回。
	Reg *meter.Registry `yaml:"-"`
}

// LimitsSpec 是一层限制(全局 limits: 或每口 inbounds[].limits:;承设计 §6.2 层1/2)。
type LimitsSpec struct {
	Rate     string `yaml:"rate"`      // 吞吐上限(500mbps/50kbps/…);空=不限
	MaxConns int64  `yaml:"max-conns"` // 连接数上限;0=不限
}

// RoutingSpec 是规则分流配置(承设计 §8.3):有序规则表 + default 兜底。有 routing: 块时,所有代理
// 入站按规则选出站(首个命中);无则退回每口 outbound: 静态绑定。
type RoutingSpec struct {
	Default       string             `yaml:"default"`        // 未命中兜底出站名(须在 outbounds 定义,或内置 direct/block)
	Rules         []RuleSpec         `yaml:"rules"`          // 有序,首个命中生效
	GeoIPPath     string             `yaml:"geoip-path"`     // geoip 库路径:.dat=V2Ray/Xray geoip.dat,其余=MaxMind mmdb(有 geoip 规则时必给)
	GeoSitePath   string             `yaml:"geosite-path"`   // geosite.dat 路径(V2Ray/mihomo 格式;有 geosite 规则时必给)
	RuleProviders []RuleProviderSpec `yaml:"rule-providers"` // 命名规则集(本地文件/远程 URL 经 detour 拉;Surge/Clash 文本)
}

// RuleProviderSpec 是一个命名规则集来源(Surge/Clash 文本 domain-list/ip-list/classical)。
type RuleProviderSpec struct {
	Name     string `yaml:"name"`
	Behavior string `yaml:"behavior"` // domain | ipcidr | classical
	Path     string `yaml:"path"`     // 本地文件(与 url 二选一)
	URL      string `yaml:"url"`      // 远程 URL(经 detour 拉)
	Detour   string `yaml:"detour"`   // 拉取远程用的出站名
	Interval string `yaml:"interval"` // (预留)定时更新周期
}

// RuleSpec 是一条分流规则:恰好一个维度谓词 + to(目标出站/链名)。v1 维度:域名(精确/后缀/关键字)、
// ip-cidr、端口。network/geoip/geosite/rule-set/and-or-not 为后续增量(承 §8.3.2 全集)。
type RuleSpec struct {
	Domain        []string `yaml:"domain"`         // 精确域名
	DomainSuffix  []string `yaml:"domain-suffix"`  // 域名后缀(标签边界)
	DomainKeyword []string `yaml:"domain-keyword"` // 域名子串
	IPCIDR        []string `yaml:"ip-cidr"`        // CIDR(仅对 IP 目标)
	Port          []uint16 `yaml:"port"`           // 目标端口
	Network       []string `yaml:"network"`        // 传输层网络(tcp/udp)
	GeoIP         []string `yaml:"geoip"`          // geoip 国码(如 [CN,US];仅对 IP 目标;需 routing.geoip-path)
	GeoSite       []string `yaml:"geosite"`        // geosite 类目(如 [google,cn];仅对域名目标;需 routing.geosite-path)
	RuleSet       []string `yaml:"rule-set"`       // 引用 rule-providers 里的规则集名(按其 behavior 判域名/IP)
	ProcessName   []string `yaml:"process-name"`   // 发起进程可执行名(basename,精确;仅对本机入站有意义;仅 Linux)
	ProcessPath   []string `yaml:"process-path"`   // 发起进程可执行完整路径(精确;仅 Linux)

	// 逻辑组合(and/or/not):op 非空 → 组合规则,叶子维度须空、sub 为子规则列表、not 取反。
	Op  string     `yaml:"op"`  // and / or
	Sub []RuleSpec `yaml:"sub"` // 子规则(叶子或嵌套组合;不带 to)
	Not bool       `yaml:"not"` // 组合结果取反

	To string `yaml:"to"` // 命中派发到的出站名(组合规则也用)
}

// MetricsSpec 是 metrics: 配置块(承设计 §5,MVP)。listen 非空 → 开启按用户计量 + HTTP 快照/控制端点。
//
// ★安全:该端点含 Disable/Enable/Kill 等【运维控制】权力,故默认【仅本机】可访问。access 显式放开:
//   - 缺省 / 空:仅 127.0.0.0/8 + ::1(本机)—— 哪怕 listen 绑 0.0.0.0 也只放本机
//   - 单 IP:["203.0.113.7"]   多 IP / 网段:["10.0.0.0/8", "192.168.1.5"]   全开(慎):["0.0.0.0/0","::/0"]
type MetricsSpec struct {
	Listen string   `yaml:"listen"` // 统计/控制端点监听地址(建议 127.0.0.1:9091)
	Access []string `yaml:"access"` // 允许访问的 IP / CIDR 白名单;空 = 仅本机
}

// DNSSpec 是 dns: 配置块(承设计 §10.1.8)。MVP:明文 UDP/TCP 上游 + 缓存 + race/sequential。
type DNSSpec struct {
	Enabled     bool                   `yaml:"enabled"`
	Detour      string                 `yaml:"detour"`   // 未写 detour 的 nameserver 默认出站(必具名)
	Strategy    string                 `yaml:"strategy"` // race(默认)| sequential
	Nameservers []NameserverSpec       `yaml:"nameservers"`
	Policies    []NameserverPolicySpec `yaml:"nameserver-policy"` // 按域名选上游(不同域名走不同 DNS 上游)
	Hosts       map[string][]string    `yaml:"hosts"`             // 静态 host→IP,命中不走上游(也防这些域名 DNS 泄漏)
	FakeIP      *FakeIPSpec            `yaml:"fake-ip"`           // fake-ip:给域名发伪 IP,让只见 IP 的连接也能按域名分流
}

// FakeIPSpec 是 dns.fake-ip 块:enabled + v4/v6 伪 IP 段 + 排除后缀。
type FakeIPSpec struct {
	Enabled    bool     `yaml:"enabled"`
	Inet4Range string   `yaml:"inet4-range"` // 默认 198.18.0.0/15
	Inet6Range string   `yaml:"inet6-range"` // 空=不发 v6 伪 IP(AAAA 空答)
	Exclude    []string `yaml:"exclude"`     // 排除域名后缀,命中走真解析
}

// NameserverSpec 是一台上游:tag + address(udp/tcp/tls(DoT)/https(DoH))+ 绑定的具名出站(防泄漏)。
type NameserverSpec struct {
	Tag      string `yaml:"tag"`
	Address  string `yaml:"address"`
	SNI      string `yaml:"sni"`      // DoT/DoH:TLS ServerName(可空→取地址 host)
	Insecure bool   `yaml:"insecure"` // DoT/DoH:跳过证书校验
	Detour   string `yaml:"detour"`
}

// NameserverPolicySpec 是一条 nameserver-policy:域名维度(任一命中)→ 命中时用的上游 tag 子集
// (引用 nameservers 里的 tag;让不同域名走不同 DNS 上游,对齐 mihomo nameserver-policy)。
type NameserverPolicySpec struct {
	Domain        []string `yaml:"domain"`         // 精确域名
	DomainSuffix  []string `yaml:"domain-suffix"`  // 域名后缀(标签边界)
	DomainKeyword []string `yaml:"domain-keyword"` // 域名子串
	Nameserver    []string `yaml:"nameserver"`     // 命中用的上游 tag(≥1)
}

// Bridge 是一个反连隧道:经 Portal 出站(任意代理)拨到公网 Portal,把用户流量反向复用
// 回来、由本机直连落地到内网。协议无关(隧道用哪个代理由 Portal 出站决定)。
type Bridge struct {
	Portal        string `yaml:"portal"`         // 引用一个 outbound 名(拨 Portal 的代理出站)
	ControlDomain string `yaml:"control-domain"` // 隧道注册域(默认 reverse.ntr,须与 Portal 一致)
	Pool          int    `yaml:"pool"`           // 维持的隧道数(默认 1)
}

// Inbound 是一个入站:监听地址 + 底→顶层栈 + 用户 + 路由到哪个出站。
// Type 空/"proxy" = 流式栈模型;"anytls" 等 = 会话式协议(不走栈)。
type Inbound struct {
	Name          string           `yaml:"name"`    // 口名(第4章):users[].on/off 引用它,BillID=<user>@<口名>;缺省用 listen 兜底
	Listen        string           `yaml:"listen"`  // 旧格式 host:port;第4章写 host(缺省 0.0.0.0)配 port
	Port          uint16           `yaml:"port"`    // 第4章:监听端口;非零时 listen 只写 host
	Type          string           `yaml:"type"`    // 第4章:协议名(vless/trojan/snell…,由 registry 判定)或形态(tun/tproxy/portal/会话式)
	Extra         map[string]any   `yaml:",inline"` // 第4章新格式:所有未声明键 —— 层块(reality:/ws:/shadowtls:…)与协议专属字段(flow/version…),synthLayers 分拣
	Layers        []map[string]any `yaml:"layers"`
	Users         []map[string]any `yaml:"users"`
	TLS           map[string]any   `yaml:"tls"`
	Obfs          string           `yaml:"obfs"` // hysteria1 salamander 混淆口令(可空)
	Outbound      string           `yaml:"outbound"`
	Sniff         bool             `yaml:"sniff"`          // 开启域名嗅探:IP 目标 peek 首包 SNI/Host 解真域名再分流(承 §10.4.2)
	ControlDomain string           `yaml:"control-domain"` // type=portal:Bridge 连接的注册域(默认 reverse.ntr)
	AssignAddress string           `yaml:"assign-address"` // type=connect-ip:下发给客户端的隧道内地址(CIDR)
	MTU           int              `yaml:"mtu"`            // type=connect-ip / type=tun
	Transport     string           `yaml:"transport"`      // type=mieru:mieru 传输协议 TCP/UDP(默认 TCP)
	Address       []string         `yaml:"address"`        // type=tun:TUN 网卡地址 CIDR(至少一个)
	IfName        string           `yaml:"if-name"`        // type=tun:接口名(空=平台默认)
	DNSHijack     []string         `yaml:"dns-hijack"`     // type=tun:劫持的 DNS 目标(如 ["any:53"] 或 "10.0.0.1:53"),就地由内置 resolver 应答
	AutoRoute     bool             `yaml:"auto-route"`     // type=tun:自动配 split-default 路由导流入 tun(footgun,仅 Linux + CAP_NET_ADMIN + iproute2)
	RouteExclude  []string         `yaml:"route-exclude"`  // type=tun:auto-route 时经原网关直连的 IP(每个 proxy 出站的 server 地址,防回环)
	Target        string           `yaml:"target"`         // type=tunnel:固定目标 host:port
	Network       []string         `yaml:"network"`        // type=tunnel/tproxy:tcp/udp(空=两者)
	Limits        *LimitsSpec      `yaml:"limits"`         // 每口限制(承设计 §6.2 层2:单口隔离)
	Fallback      string           `yaml:"fallback"`       // 回落伪装站 host:port:协议握手失败时把连接中继到该真站(抗探测)
	Fallbacks     []FallbackSpec   `yaml:"fallbacks"`      // 多站回落:按 ALPN + HTTP path 前缀选伪装站(对齐 xray fallbacks;非空优先于 fallback)
}

// inboundName 口名:name 字段;缺省用监听地址兜底(旧格式无 name 的口仍可被 users 引用)。
func (in Inbound) inboundName() string {
	if in.Name != "" {
		return in.Name
	}
	return in.listenAddr()
}

// listenAddr 合成监听地址:第4章 listen(host,缺省 0.0.0.0)+ port;旧格式 listen 已是 host:port 则原样。
// ★幂等:Build 会把合成结果写回 in.Listen 再次调用,若 Listen 已含端口则不再拼接
// (否则第二次会变成 "[0.0.0.0:2053]:2053",口名对不上、凭据静默丢失)。
func (in Inbound) listenAddr() string {
	if in.Port == 0 {
		return in.Listen
	}
	if _, _, err := net.SplitHostPort(in.Listen); err == nil {
		return in.Listen // 已是 host:port
	}
	host := in.Listen
	if host == "" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(int(in.Port)))
}

// isProxyProto 报 name 是否注册为 Band=Proxy 的终端协议(vless/trojan/snell/ss/…)。
// config 层【不枚举协议名】,全靠 registry 自报 —— 核心零 switch 的落点。
func isProxyProto(name string) bool {
	d, ok := registry.Lookup(name)
	return ok && d.Band() == registry.BandProxy
}

// newFormat 报此口是第4章新格式:type 为注册的终端协议名,且未写旧 layers 数组。
func (in Inbound) newFormat() bool { return len(in.Layers) == 0 && isProxyProto(in.Type) }

// synthStack 是入站/出站共用的层集合成(第4章新格式),交 buildStack(顺序无关,compile.Order 按 Band
// 排、书写序不参与):
//   - 旧格式(layers 数组非空):原样 toLayerSpecs —— 兼容垫片,脚本迁完即拆。
//   - 新格式(typ=协议名):extra 里「键是注册层插件且值为映射」→ 一层(tls:/reality:/ws:/grpc:/shadowtls:/
//     mkcp:…);其余键(flow/version/cipher/psk…)→ 归终端协议字段;tls 参数非空 → tls 层(入站 tls: 是具名字段)。
//     config 不认识任何协议名,分拣全靠 registry.Lookup。
func synthStack(typ string, layers []map[string]any, extra, tls map[string]any) ([]service.LayerSpec, error) {
	if len(layers) > 0 {
		if len(extra) > 0 { // 旧 layers 数组与新格式 inline 层块/字段混写:后者会被静默丢弃 → 直接判死
			return nil, fmt.Errorf("旧 layers 数组不能与新格式层块/协议字段混写(多余键 %s);二选一", sortedKeysAny(extra))
		}
		return toLayerSpecs(layers)
	}
	if !isProxyProto(typ) {
		return nil, fmt.Errorf("type %q 不是注册的终端协议,且未写 layers", typ)
	}
	var specs []service.LayerSpec
	protoFields := make(map[string]any)
	for k, v := range extra {
		m, isMap := v.(map[string]any)
		_, isLayer := registry.Lookup(k)
		switch {
		case isLayer && isMap:
			node, err := mapToNode(m, "")
			if err != nil {
				return nil, fmt.Errorf("层 %q:%w", k, err)
			}
			specs = append(specs, service.LayerSpec{Name: k, Node: node})
		case isLayer && !isMap: // 层名写成标量:该层会静默缺席(如 tls 退化明文)→ 判死
			return nil, fmt.Errorf("层 %q 须写成块式映射(不能是标量/列表),否则该层静默缺席", k)
		case !isLayer && isMap: // 映射值却不是注册层:十有八九是拼错的层名(relaity:)→ 判死,不静默吞成协议字段
			return nil, fmt.Errorf("未知层块 %q:不是注册的层插件(协议专属字段应为标量,层块名请核对拼写)", k)
		default:
			protoFields[k] = v
		}
	}
	if len(tls) > 0 {
		node, err := mapToNode(tls, "")
		if err != nil {
			return nil, fmt.Errorf("层 tls:%w", err)
		}
		specs = append(specs, service.LayerSpec{Name: "tls", Node: node})
	}
	node, err := mapToNode(protoFields, "")
	if err != nil {
		return nil, fmt.Errorf("协议 %q 字段:%w", typ, err)
	}
	specs = append(specs, service.LayerSpec{Name: typ, Node: node})
	return specs, nil
}

// synthLayers 入站:tls: 是 Inbound 具名字段(会话式共用),新格式下即 tls 层。
func (in Inbound) synthLayers() ([]service.LayerSpec, error) {
	return synthStack(in.Type, in.Layers, in.Extra, in.TLS)
}

// newFormat 出站镜像入站:type=协议名(vless/trojan/snell…)+ server/secret + 层块 + 协议字段,未写 layers。
// 出站没有 tls 具名字段,tls: 自然落 Extra、经 Lookup 成层;sni/insecure/指纹写在 tls: 块里。
func (o Outbound) newFormat() bool { return len(o.Layers) == 0 && isProxyProto(o.Type) }

// synthLayers 出站:同入站分拣,无具名 tls 字段。
func (o Outbound) synthLayers() ([]service.LayerSpec, error) {
	return synthStack(o.Type, o.Layers, o.Extra, nil)
}

// authProto 该口的 per-user 认证协议(= 栈顶协议名,供 Desugar 按栈取密钥,§4.4 规则 3)。
// 新格式:type 即终端协议;旧格式流式栈(空/proxy/portal):取 layers 最后一层 type。空 = 不产 binding。
// 会话式(anytls/hysteria2/tuic…)各自持 users map、未接 cred/meter(蓝图世界 C),暂返空;
// 多层认证(shadowtls 外层)待 Descriptor 自报 + 传输层参与 auth(蓝图骨头 4),当前单层。
func (in Inbound) authProto() string {
	if in.newFormat() {
		return in.Type
	}
	switch in.Type {
	case "", "proxy", "portal":
		if n := len(in.Layers); n > 0 {
			if t, _ := in.Layers[n-1]["type"].(string); t != "" {
				return t
			}
		}
	}
	return ""
}

// FallbackSpec 是一条多站回落规则(对齐 xray fallbacks 的 name/alpn/path/dest)。
type FallbackSpec struct {
	SNI  []string `yaml:"sni"`  // 空=任意 ClientHello ServerName(对齐 xray name 维)
	ALPN []string `yaml:"alpn"` // 空=任意协商 ALPN
	Path string   `yaml:"path"` // 空=任意;非空=HTTP 请求首行 path 前缀匹配
	Dest string   `yaml:"dest"` // 伪装站 host:port
	Xver int      `yaml:"xver"` // 0=不发、1=PROXY protocol v1、2=v2:向伪装站先发 PROXY 头带真实客户端 IP
}

// Outbound 是一个出站:direct / proxy(拨上游,含层栈 + 凭据)/ anytls 等会话式。
type Outbound struct {
	Name        string           `yaml:"name"`
	Type        string           `yaml:"type"`
	Server      string           `yaml:"server"`
	Layers      []map[string]any `yaml:"layers"`  // 旧格式显式栈(兼容垫片);新格式不写
	Extra       map[string]any   `yaml:",inline"` // 第4章新格式:未声明键 —— 层块(tls:/reality:/ws:…)与协议字段(flow…),synthLayers 分拣
	Secret      string           `yaml:"secret"`
	UUID        string           `yaml:"uuid"`
	SNI         string           `yaml:"sni"`
	Obfs        string           `yaml:"obfs"` // hysteria1 salamander 混淆口令(可空)
	Insecure    bool             `yaml:"insecure"`
	FullCone    bool             `yaml:"full-cone"`          // type=direct:UDP 用 unconnected 单端口(endpoint-independent = full-cone NAT)
	Dialer      string           `yaml:"dialer"`             // relay 多跳/dialerProxy:底层连接经此具名 stream 出站(多级链天然支持)
	User        string           `yaml:"user"`               // ssh 登录用户(默认 root)
	PrivateKey  string           `yaml:"private-key"`        // ssh 出站私钥 PEM(与 secret 密码二选一)
	HostKey     string           `yaml:"host-key"`           // ssh 出站固定服务端 host key(authorized_keys 单行,可空)
	Fingerprint string           `yaml:"client-fingerprint"` // uTLS 客户端指纹(chrome/firefox/safari/ios/edge/random)
	// WireGuard(type=wireguard;需 -tags with_wireguard 构建才可用)
	PeerPublicKey string   `yaml:"peer-public-key"`
	PresharedKey  string   `yaml:"preshared-key"`
	LocalAddress  []string `yaml:"local-address"`
	AllowedIPs    []string `yaml:"allowed-ips"`
	DNS           []string `yaml:"dns"`
	MTU           int      `yaml:"mtu"`
	Keepalive     int      `yaml:"keepalive"`
	// CONNECT-IP(type=connect-ip;需 -tags with_connectip 构建才可用)
	Protocol              string `yaml:"protocol"` // :protocol 值(默认 connect-ip)
	Preset                string `yaml:"preset"`   // cloudflare = 一键套用 WARP 的三处非标差异
	URITemplate           string `yaml:"uri-template"`
	IgnoreExtendedConnect bool   `yaml:"ignore-extended-connect"`
	ClientCert            string `yaml:"client-cert"`
	ClientKey             string `yaml:"client-key"`
	// 多路复用(sing 家族 h2mux/smux/yamux;包在 type=proxy 之上,与 sing-box/mihomo 互通)。
	// 出现该块即启用;base 协议由 layers 决定(mux 用它把承载连接拨到魔术目标)。
	Mux *MuxSpec `yaml:"mux"`
	// block(type=block;内置阻断出站)。mode: reject(默认,立拒)| drop(静默黑洞)。
	Mode string `yaml:"mode"`
	// mieru(type=mieru;会话式,用户名+口令走 user/secret)
	Transport    string `yaml:"transport"`    // mieru 传输协议 TCP/UDP(默认 TCP)
	Multiplexing string `yaml:"multiplexing"` // mieru 多路复用等级(可选:MULTIPLEXING_OFF/LOW/MIDDLE/HIGH)

	// 策略组(type=select/urltest/fallback/load-balance):在多个子出站间选路。
	Outbounds []string `yaml:"outbounds"` // 组成员出站名(可含其它组,禁成环)
	Default   string   `yaml:"default"`   // select/初始选中成员名(空=第一个)
	URL       string   `yaml:"url"`       // urltest/fallback 探测 URL(默认 http://www.gstatic.com/generate_204)
	Interval  string   `yaml:"interval"`  // 探测周期(如 5m,默认 5m)
	Tolerance int      `yaml:"tolerance"` // urltest 抖动容差 ms
	LB        string   `yaml:"lb"`        // load-balance 模式:round-robin(默认)| consistent-hashing
}

// MuxSpec 是 mux 出站配置(对齐 sing-box multiplex 语义)。
type MuxSpec struct {
	Protocol       string `yaml:"protocol"` // h2mux(默认)/smux/yamux
	MaxConnections int    `yaml:"max-connections"`
	MinStreams     int    `yaml:"min-streams"`
	MaxStreams     int    `yaml:"max-streams"`
	Padding        bool   `yaml:"padding"`
}

// Instance 是一个可运行入站。TCP 流式入站给 Listen+Handler(由 runtime 建 TCP 监听 + Serve);
// 自管监听的会话式入站(hy2/tuic 的 UDP/QUIC)给 Run(自己绑监听、阻塞至 ctx 取消)。
type Instance struct {
	Listen  string
	Handler endpoint.InboundHandler
	Run     func(ctx context.Context) error
	Hash    string // 源配置的语义哈希(热重载 diff 用:同 Listen 但 Hash 变 = 重启该口 / Drain)
}

// Load 从路径读并解析 YAML 配置。
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("config: 解析 YAML 失败:%w", err)
	}
	return &f, nil
}

// buildResolver 从 dns: 块建 route.Resolver:每 nameserver 的 detour 从 outs 解析(必具名、防泄漏)。
func buildResolver(spec *DNSSpec, outs map[string]endpoint.Outbound) (route.Resolver, error) {
	if spec == nil || !spec.Enabled {
		return nil, fmt.Errorf("config: 使用了 type=dns 出站,但未启用 dns:(需 dns.enabled=true)")
	}
	if len(spec.Nameservers) == 0 {
		return nil, fmt.Errorf("config: dns 至少需一个 nameserver")
	}
	resolveDetour := func(name string) (endpoint.Outbound, error) {
		if name == "" {
			name = spec.Detour // 默认 detour
		}
		if name == "" {
			return nil, fmt.Errorf("config: dns nameserver 缺 detour 出站且无默认 dns.detour(绝不隐式直连)")
		}
		out, ok := outs[name]
		if !ok {
			return nil, fmt.Errorf("config: dns nameserver detour 引用未定义出站 %q", name)
		}
		return out, nil
	}
	var nss []dns.Nameserver
	for _, ns := range spec.Nameservers {
		det, err := resolveDetour(ns.Detour)
		if err != nil {
			return nil, err
		}
		nss = append(nss, dns.Nameserver{Tag: ns.Tag, Address: ns.Address, SNI: ns.SNI, Insecure: ns.Insecure, Detour: det})
	}
	hosts, err := parseHosts(spec.Hosts)
	if err != nil {
		return nil, err
	}
	fake, err := parseFakeIP(spec.FakeIP)
	if err != nil {
		return nil, err
	}
	var policies []dns.NameserverPolicy
	for _, pol := range spec.Policies {
		policies = append(policies, dns.NameserverPolicy{
			Domain:        pol.Domain,
			DomainSuffix:  pol.DomainSuffix,
			DomainKeyword: pol.DomainKeyword,
			Nameservers:   pol.Nameserver,
		})
	}
	return dns.New(nss, policies, spec.Strategy, hosts, fake)
}

// parseFakeIP 把 config 的 fake-ip 块解析成 *dns.FakeIPConfig(未启用→nil)。默认 v4 198.18.0.0/15。
func parseFakeIP(spec *FakeIPSpec) (*dns.FakeIPConfig, error) {
	if spec == nil || !spec.Enabled {
		return nil, nil
	}
	v4s := spec.Inet4Range
	if v4s == "" {
		v4s = "198.18.0.0/15"
	}
	v4, err := netip.ParsePrefix(v4s)
	if err != nil {
		return nil, fmt.Errorf("config: dns.fake-ip.inet4-range %q:%w", v4s, err)
	}
	if !v4.Addr().Unmap().Is4() {
		return nil, fmt.Errorf("config: dns.fake-ip.inet4-range %q 不是 IPv4 段", v4s)
	}
	cfg := &dns.FakeIPConfig{Inet4: v4.Masked(), Exclude: spec.Exclude}
	if spec.Inet6Range != "" {
		v6, err := netip.ParsePrefix(spec.Inet6Range)
		if err != nil {
			return nil, fmt.Errorf("config: dns.fake-ip.inet6-range %q:%w", spec.Inet6Range, err)
		}
		if !v6.Addr().Is6() || v6.Addr().Is4In6() {
			return nil, fmt.Errorf("config: dns.fake-ip.inet6-range %q 不是 IPv6 段", spec.Inet6Range)
		}
		cfg.Inet6 = v6.Masked()
	}
	return cfg, nil
}

// parseHosts 把 config 的 hosts(域名→IP 字符串列表)解析成 netip.Addr(非法 IP 大声报)。
func parseHosts(in map[string][]string) (map[string][]netip.Addr, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string][]netip.Addr, len(in))
	for name, ips := range in {
		for _, s := range ips {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("config: dns.hosts[%q] 非法 IP %q:%w", name, s, err)
			}
			out[name] = append(out[name], ip)
		}
	}
	return out, nil
}

// parseHijack 把 tun 的 dns-hijack 目标(["any:53","10.0.0.1:53"])解析成 []netip.AddrPort。
// "any"/"*" → 0.0.0.0(unspecified,匹配任意该端口目标);缺端口默认 53。
func parseHijack(in []string) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, s := range in {
		host, port := s, "53"
		if h, p, err := net.SplitHostPort(s); err == nil {
			host, port = h, p
		}
		pn, err := strconv.Atoi(port)
		if err != nil || pn <= 0 || pn > 65535 {
			return nil, fmt.Errorf("dns-hijack 端口非法 %q", s)
		}
		var ip netip.Addr
		if host == "any" || host == "*" || host == "" {
			ip = netip.IPv4Unspecified()
		} else {
			ip, err = netip.ParseAddr(host)
			if err != nil {
				return nil, fmt.Errorf("dns-hijack 地址非法 %q:%w", s, err)
			}
		}
		out = append(out, netip.AddrPortFrom(ip, uint16(pn)))
	}
	return out, nil
}

// buildGroups 第二趟建策略组:迭代地把成员名从 outs 解析成真出站(组成员可前向引用/是别的组);
// 一整趟无进展 = 成环或成员悬空 → 大声报(守 NTR「非法组合装配期判死」纪律,不静默退化)。
// 返回需要后台探测的组(urltest/fallback/load-balance),供调用方挂成 health-loop Instance。
func buildGroups(pending []Outbound, outs map[string]endpoint.Outbound) ([]*group.Group, error) {
	if len(pending) == 0 {
		return nil, nil
	}
	isGroup := make(map[string]bool, len(pending))
	for _, o := range pending {
		isGroup[o.Name] = true
	}
	var loops []*group.Group
	remaining := pending
	for len(remaining) > 0 {
		var next []Outbound
		progress := false
		for _, o := range remaining {
			ready := true
			var members []group.Member
			for _, mn := range o.Outbounds {
				out, ok := outs[mn]
				if !ok {
					if isGroup[mn] { // 是组但还没建 → 等下一轮
						ready = false
						break
					}
					return nil, fmt.Errorf("config: 策略组 %q 成员 %q 未定义出站", o.Name, mn)
				}
				members = append(members, group.Member{Name: mn, Out: out})
			}
			if !ready {
				next = append(next, o)
				continue
			}
			g, err := buildOneGroup(o, members)
			if err != nil {
				return nil, err
			}
			outs[o.Name] = g
			if g.NeedsHealth() {
				loops = append(loops, g)
			}
			progress = true
		}
		if !progress {
			var stuck []string
			for _, o := range next {
				stuck = append(stuck, o.Name)
			}
			return nil, fmt.Errorf("config: 策略组成环或成员悬空(无法拓扑建成):%v", stuck)
		}
		remaining = next
	}
	return loops, nil
}

func buildOneGroup(o Outbound, members []group.Member) (*group.Group, error) {
	var strat group.Strategy
	switch o.Type {
	case "select":
		strat = group.Select
	case "urltest":
		strat = group.URLTest
	case "fallback":
		strat = group.Fallback
	case "load-balance":
		strat = group.LoadBalance
	}
	interval := 5 * time.Minute
	if o.Interval != "" {
		if d, err := time.ParseDuration(o.Interval); err == nil {
			interval = d
		} else {
			return nil, fmt.Errorf("config: 策略组 %q interval %q:%w", o.Name, o.Interval, err)
		}
	}
	return group.New(group.Options{
		Name: o.Name, Members: members, Strategy: strat, Default: o.Default,
		TestURL: o.URL, Interval: interval, Tolerance: o.Tolerance,
		LBHash: o.LB == "consistent-hashing" || o.LB == "hash",
	})
}

// wireDialers 实现 relay 多跳/dialerProxy:把配了 dialer 的 stream 出站的底层拨号接到另一具名出站。
// 全部出站建好后第二趟设 BaseDial(闭包运行时查 outs → 天然支持多级链 A→B→C);先做环检测。
func wireDialers(specs []Outbound, outs map[string]endpoint.Outbound) error {
	edge := map[string]string{}
	for _, o := range specs {
		if o.Dialer != "" {
			edge[o.Name] = o.Dialer
		}
	}
	for start := range edge { // 环检测:沿单出边走,重复即环
		seen := map[string]bool{}
		for n := start; n != ""; n = edge[n] {
			if seen[n] {
				return fmt.Errorf("config: dialer 链成环(涉及出站 %q)", n)
			}
			seen[n] = true
		}
	}
	for _, o := range specs {
		if o.Dialer == "" {
			continue
		}
		if _, ok := outs[o.Dialer]; !ok {
			return fmt.Errorf("config: 出站 %q 的 dialer %q 未定义", o.Name, o.Dialer)
		}
		p, ok := outs[o.Name].(*upstream.Outbound)
		if !ok {
			return fmt.Errorf("config: 出站 %q 非 stream 类,不支持 dialer(会话式协议自管连接)", o.Name)
		}
		dst, err := parseDialTarget(p.Server)
		if err != nil {
			return fmt.Errorf("config: 出站 %q 的 dialer 上游地址 %q 非法: %w", o.Name, p.Server, err)
		}
		name := o.Dialer
		// BaseDial 收 host:port 字符串(dialBase 传入的是 p.Server);经具名 dialer 出站拨到该上游。
		p.BaseDial = func(ctx context.Context, server string) (link.Stream, error) {
			return outs[name].DialStream(ctx, dst)
		}
	}
	return nil
}

// parseDialTarget 把 "host:port" 拆成 Socksaddr(IP→FromIPPort,域名→FromFqdn),
// 与 mtproto/snell/ruleset 等处既有解析范式一致;供 relay dialer 链在建栈期解析上游地址。
func parseDialTarget(server string) (addr.Socksaddr, error) {
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return addr.Socksaddr{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return addr.Socksaddr{}, fmt.Errorf("端口 %q 非法: %w", portStr, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return addr.FromIPPort(netip.AddrPortFrom(ip, uint16(port))), nil
	}
	return addr.FromFqdn(host, uint16(port)), nil
}

// buildRouter 把 routing: 块编译成 rule.Engine:转换规则、校验 default 与每条 to 均为已定义出站
// (编译期挡住悬空目标,守「绝不静默误路由」)。规则维度校验(须恰好一个)在 rule.Compile 内。
func buildRouter(ctx context.Context, spec *RoutingSpec, outs map[string]endpoint.Outbound) (*rule.Engine, error) {
	if _, ok := outs[spec.Default]; !ok {
		return nil, fmt.Errorf("config: routing.default %q 未在 outbounds 定义", spec.Default)
	}
	// rule-providers:按名建规则集(本地文件/远程 URL 经 detour 拉)。
	providers := make(map[string]*ruleset.Provider, len(spec.RuleProviders))
	for _, ps := range spec.RuleProviders {
		var det endpoint.Outbound
		if ps.URL != "" {
			name := ps.Detour
			if name == "" {
				return nil, fmt.Errorf("config: rule-provider %q 是远程 url,需 detour 出站(绝不隐式直连)", ps.Name)
			}
			d, ok := outs[name]
			if !ok {
				return nil, fmt.Errorf("config: rule-provider %q detour %q 未在 outbounds 定义", ps.Name, name)
			}
			det = d
		}
		providers[ps.Name] = &ruleset.Provider{Name: ps.Name, Behavior: ps.Behavior, Path: ps.Path, URL: ps.URL, Detour: det}
	}
	// walkSpecs 递归遍历规则及其组合子规则(用于 geoip/geosite 是否被用到的探测,含 sub)。
	var walkSpecs func([]RuleSpec, func(RuleSpec))
	walkSpecs = func(rs []RuleSpec, fn func(RuleSpec)) {
		for _, r := range rs {
			fn(r)
			if len(r.Sub) > 0 {
				walkSpecs(r.Sub, fn)
			}
		}
	}
	// 有 geoip 规则(含组合子规则里的)则打开 IP 库(一次,共享)。geoip-path 兼容两大格式:
	// .dat 后缀 → V2Ray/Xray geoip.dat(protobuf);其余 → MaxMind mmdb。二者都产出 rule.IPSet,引擎无感。
	var geoSetFor func([]string) (rule.IPSet, error)
	needGeoIP := false
	walkSpecs(spec.Rules, func(r RuleSpec) {
		if len(r.GeoIP) > 0 {
			needGeoIP = true
		}
	})
	if needGeoIP {
		if spec.GeoIPPath == "" {
			return nil, fmt.Errorf("config: 用了 geoip 规则但缺 routing.geoip-path(mmdb 或 V2Ray geoip.dat 路径)")
		}
		if strings.HasSuffix(strings.ToLower(spec.GeoIPPath), ".dat") {
			db, err := geo.OpenGeoIPDat(spec.GeoIPPath)
			if err != nil {
				return nil, err
			}
			geoSetFor = db.CountrySet
		} else {
			db, err := geo.OpenGeoIP(spec.GeoIPPath)
			if err != nil {
				return nil, err
			}
			geoSetFor = func(codes []string) (rule.IPSet, error) { return db.CountrySet(codes), nil }
		}
	}
	// 有 geosite 规则(含组合子规则里的)则打开 geosite.dat(一次,共享)。
	var siteDB *geo.GeoSiteDB
	needGeoSite := false
	walkSpecs(spec.Rules, func(r RuleSpec) {
		if len(r.GeoSite) > 0 {
			needGeoSite = true
		}
	})
	if needGeoSite {
		if spec.GeoSitePath == "" {
			return nil, fmt.Errorf("config: 用了 geosite 规则但缺 routing.geosite-path(geosite.dat 路径)")
		}
		db, err := geo.OpenGeoSite(spec.GeoSitePath)
		if err != nil {
			return nil, err
		}
		siteDB = db
	}
	// specToRule 递归把一条 RuleSpec 转 rule.Rule(组合规则递归 sub;叶子物化 geoip/geosite/rule-set)。
	var specToRule func(RuleSpec) (rule.Rule, error)
	specToRule = func(rs RuleSpec) (rule.Rule, error) {
		if rs.Op != "" { // 组合规则:递归子规则(子规则不带 to、维度校验交 rule.Compile)
			r := rule.Rule{Op: rs.Op, Not: rs.Not, To: rs.To}
			for _, sub := range rs.Sub {
				sr, err := specToRule(sub)
				if err != nil {
					return rule.Rule{}, err
				}
				r.Sub = append(r.Sub, sr)
			}
			return r, nil
		}
		var geoSets []rule.IPSet
		if len(rs.GeoIP) > 0 {
			set, err := geoSetFor(rs.GeoIP)
			if err != nil {
				return rule.Rule{}, fmt.Errorf("geoip:%w", err)
			}
			geoSets = append(geoSets, set)
		}
		var siteSets []rule.DomainSet
		for _, code := range rs.GeoSite {
			ds, err := siteDB.DomainSet(code)
			if err != nil {
				return rule.Rule{}, fmt.Errorf("geosite:%w", err)
			}
			siteSets = append(siteSets, ds)
		}
		// rule-set:按 provider 的 behavior 归入域名集(domain/classical)或 IP 集(ipcidr)。
		for _, name := range rs.RuleSet {
			pv, ok := providers[name]
			if !ok {
				return rule.Rule{}, fmt.Errorf("rule-set 引用未定义 provider %q", name)
			}
			if pv.Behavior == "ipcidr" {
				ips, err := pv.LoadIP(ctx)
				if err != nil {
					return rule.Rule{}, err
				}
				geoSets = append(geoSets, ips)
			} else {
				ds, err := pv.LoadDomain(ctx)
				if err != nil {
					return rule.Rule{}, err
				}
				siteSets = append(siteSets, ds)
			}
		}
		return rule.Rule{
			Domain:        rs.Domain,
			DomainSuffix:  rs.DomainSuffix,
			DomainKeyword: rs.DomainKeyword,
			IPCIDR:        rs.IPCIDR,
			Port:          rs.Port,
			Network:       rs.Network,
			GeoIP:         geoSets,
			GeoSite:       siteSets,
			ProcessName:   rs.ProcessName,
			ProcessPath:   rs.ProcessPath,
			To:            rs.To,
		}, nil
	}
	rules := make([]rule.Rule, len(spec.Rules))
	for i, rs := range spec.Rules {
		if _, ok := outs[rs.To]; !ok { // 顶层规则的 to 必须是已定义出站(子规则 to 空,不校验)
			return nil, fmt.Errorf("config: routing.rules[%d].to %q 未在 outbounds 定义", i, rs.To)
		}
		r, err := specToRule(rs)
		if err != nil {
			return nil, fmt.Errorf("config: routing.rules[%d]:%w", i, err)
		}
		rules[i] = r
	}
	return rule.Compile(rules, spec.Default)
}

// Build 把配置装配成可运行入站列表(解析出站表 → 逐入站建栈 + 注册用户 + 绑定出站)。
// 热重载路径:调用前设 f.Reg(注入既有计量注册表,跨代复用保累计流量 + 保 metrics 端点);Build 会把
// 实际使用的 Registry 写回 f.Reg 供调用方读取。reg=nil 且开启 metrics 时新建。
func (f *File) Build(ctx context.Context) ([]Instance, error) {
	outs := map[string]endpoint.Outbound{"direct": direct.Outbound{}} // 恒有 direct
	var dnsOutboundNames []string                                     // type=dns 出站延迟到 resolver 建好再填
	// 注册表【常驻】:它是 BillID ↔ 数字句柄的分配权所在(跨热重载复用,id 稳定);
	// 计量/限额是否启用另看 metrics: 块 —— metricReg 非 nil 才把 pi.Meter 挂上、才设限额。
	reg := f.Reg
	if reg == nil {
		reg = meter.NewRegistry()
	}
	f.Reg = reg                   // 写回供热重载复用
	var metricReg *meter.Registry // nil = 计量关闭、零成本
	if f.Metrics != nil && f.Metrics.Listen != "" {
		metricReg = reg
	}
	globalGate, err := buildGate(f.Limits) // 全局连接闸/限速(§6.2 层1;nil=不限)
	if err != nil {
		return nil, fmt.Errorf("config: limits:%w", err)
	}
	var pendingGroups []Outbound // 策略组延迟到第二趟建(成员可前向引用/是别的组)
	for _, o := range f.Outbounds {
		if o.Name == "" {
			return nil, fmt.Errorf("config: 出站缺 name")
		}
		otyp := o.Type
		if o.newFormat() { // 第4章新格式:type=协议名 + 层块,走流式栈(同 proxy 形态)
			otyp = "proxy"
		}
		switch otyp {
		case "select", "urltest", "fallback", "load-balance":
			pendingGroups = append(pendingGroups, o) // 见出站 loop 后的第二趟
		case "direct", "":
			outs[o.Name] = direct.Outbound{FullCone: o.FullCone}
		case "dns":
			dnsOutboundNames = append(dnsOutboundNames, o.Name) // 延迟(见出站 loop 后)
		case "block":
			switch o.Mode {
			case "", "reject", "rst":
				outs[o.Name] = block.Outbound{Drop: false}
			case "drop", "silent", "blackhole":
				outs[o.Name] = block.Outbound{Drop: true}
			default:
				return nil, fmt.Errorf("config: 出站 %q(block)未知 mode %q(仅 reject/drop)", o.Name, o.Mode)
			}
		case "proxy":
			if o.newFormat() && (o.SNI != "" || o.Insecure || o.Fingerprint != "") {
				// 这几个具名字段只被会话式出站消费;流式栈出站的 TLS 参数在 tls: 块里,写顶层会被静默忽略 → 判死
				return nil, fmt.Errorf("config: 出站 %q(type %s):sni/insecure/client-fingerprint 须写在 tls: 层块内,顶层不生效", o.Name, o.Type)
			}
			layers, err := o.synthLayers() // 旧 layers 数组(垫片)或第4章 type=协议名+层块
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q:%w", o.Name, err)
			}
			up, err := service.BuildOutbound(ctx, o.Server, layers, o.Secret)
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q:%w", o.Name, err)
			}
			if o.Mux != nil { // mux 包在 base 协议之上:承载连接经 base 拨魔术目标,其上复用子流
				switch o.Mux.Protocol {
				case "cool", "mux.cool", "xray":
					// Xray Mux.cool:自研 muxcool 客户端,承载拨 v1.mux.cool:9527。
					mo, err := muxcool.NewOutbound(up, o.Mux.MaxStreams)
					if err != nil {
						return nil, fmt.Errorf("config: 出站 %q(mux.cool):%w", o.Name, err)
					}
					outs[o.Name] = mo
				default: // sing 家族 h2mux/smux/yamux
					mo, err := mux.NewOutbound(up, mux.Options{
						Protocol:       o.Mux.Protocol,
						MaxConnections: o.Mux.MaxConnections,
						MinStreams:     o.Mux.MinStreams,
						MaxStreams:     o.Mux.MaxStreams,
						Padding:        o.Mux.Padding,
					})
					if err != nil {
						return nil, fmt.Errorf("config: 出站 %q(mux):%w", o.Name, err)
					}
					outs[o.Name] = mo
				}
			} else {
				outs[o.Name] = up
			}
		case "anytls":
			up, err := anytls.NewOutbound(anytls.Options{Server: o.Server, Password: o.Secret, SNI: o.SNI, Insecure: o.Insecure})
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(anytls):%w", o.Name, err)
			}
			outs[o.Name] = up
		case "hysteria1":
			up, err := hysteria1.NewOutbound(hysteria1.Options{Server: o.Server, Password: o.Secret, Obfs: o.Obfs, SNI: o.SNI, Insecure: o.Insecure})
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(hysteria1):%w", o.Name, err)
			}
			outs[o.Name] = up
		case "hysteria2":
			up, err := hysteria2.NewOutbound(hysteria2.Options{Server: o.Server, Password: o.Secret, SNI: o.SNI, Insecure: o.Insecure, Obfs: o.Obfs})
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(hysteria2):%w", o.Name, err)
			}
			outs[o.Name] = up
		case "tuic":
			up, err := tuic.NewOutbound(tuic.Options{Server: o.Server, UUID: o.UUID, Password: o.Secret, SNI: o.SNI, Insecure: o.Insecure})
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(tuic):%w", o.Name, err)
			}
			outs[o.Name] = up
		case "shadowquic":
			up, err := shadowquic.NewOutbound(shadowquic.Options{Server: o.Server, Username: o.User, Password: o.Secret, SNI: o.SNI})
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(shadowquic):%w", o.Name, err)
			}
			outs[o.Name] = up
		case "ssh":
			up, err := sshproto.NewOutbound(sshproto.Options{Server: o.Server, User: o.User, Password: o.Secret, PrivateKey: o.PrivateKey, HostKey: o.HostKey})
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(ssh):%w", o.Name, err)
			}
			outs[o.Name] = up
		case "trusttunnel":
			up, err := trusttunnel.NewOutbound(trusttunnel.Options{Server: o.Server, User: o.User, Password: o.Secret, SNI: o.SNI, Insecure: o.Insecure, Fingerprint: o.Fingerprint})
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(trusttunnel):%w", o.Name, err)
			}
			outs[o.Name] = up
		case "naive":
			up, err := naive.NewOutbound(naive.Options{Server: o.Server, User: o.User, Password: o.Secret, SNI: o.SNI, Insecure: o.Insecure, Fingerprint: o.Fingerprint})
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(naive):%w", o.Name, err)
			}
			outs[o.Name] = up
		case "mieru":
			up, err := mieru.NewOutbound(mieru.Options{Server: o.Server, Transport: o.Transport, Username: o.User, Password: o.Secret, Multiplexing: o.Multiplexing})
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(mieru):%w", o.Name, err)
			}
			outs[o.Name] = up
		case "connect-ip":
			opts := connectip.Options{
				Server: o.Server, SNI: o.SNI, Insecure: o.Insecure,
				Protocol: o.Protocol, URITemplate: o.URITemplate,
				IgnoreExtendedConnect: o.IgnoreExtendedConnect,
				LocalAddress:          o.LocalAddress, DNS: o.DNS, MTU: o.MTU,
				ClientCert: o.ClientCert, ClientKey: o.ClientKey,
			}
			// preset=cloudflare:套用 WARP 的三处非标差异(仍可被显式字段覆盖)。
			// 依据:mihomo transport/masque/masque.go —— :protocol 用 cf-connect-ip、
			// 发已废弃的 SETTINGS_H3_DATAGRAM_00(0x276)、跳过 Extended CONNECT 校验。
			if o.Preset == "cloudflare" {
				if opts.Protocol == "" {
					opts.Protocol = "cf-connect-ip"
				}
				opts.ExtraSettings = map[uint64]uint64{0x276: 1}
				opts.IgnoreExtendedConnect = true
			}
			up, err := connectip.NewOutbound(opts)
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(connect-ip):%w", o.Name, err)
			}
			outs[o.Name] = up
		case "wireguard":
			up, err := wireguard.NewOutbound(wireguard.Options{
				PrivateKey: o.PrivateKey, PeerPublicKey: o.PeerPublicKey, PresharedKey: o.PresharedKey,
				Endpoint: o.Server, LocalAddress: o.LocalAddress, AllowedIPs: o.AllowedIPs,
				DNS: o.DNS, MTU: o.MTU, Keepalive: o.Keepalive,
			})
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(wireguard):%w", o.Name, err)
			}
			outs[o.Name] = up
		case "masque":
			up, err := masque.NewOutbound(masque.Options{Server: o.Server, User: o.User, Password: o.Secret, SNI: o.SNI, Insecure: o.Insecure})
			if err != nil {
				return nil, fmt.Errorf("config: 出站 %q(masque):%w", o.Name, err)
			}
			outs[o.Name] = up
		default:
			return nil, fmt.Errorf("config: 出站 %q 未知 type %q", o.Name, o.Type)
		}
	}

	// 第二趟:建策略组(成员此时已在 outs;组间前向引用靠迭代,成环/悬空大声报)。
	groupLoops, err := buildGroups(pendingGroups, outs)
	if err != nil {
		return nil, err
	}

	// DNS 解析子系统:建 resolver(nameserver 的 detour 从 outs 解析,防泄漏),再填 type=dns 出站。
	// dnsResolver 提升到此作用域,供 type=tun 入站的 DNS-hijack 复用(:53 就地应答、不外泄)。
	var dnsResolver route.Resolver
	if len(dnsOutboundNames) > 0 || (f.DNS != nil && f.DNS.Enabled) {
		resolver, err := buildResolver(f.DNS, outs)
		if err != nil {
			return nil, err
		}
		dnsResolver = resolver
		for _, name := range dnsOutboundNames {
			outs[name] = dnsout.New(resolver)
		}
	}

	// 规则分流引擎(承 §8.3):有 routing: 块 → 编译规则表,所有代理入站按目标(域名/IP/端口)分流,
	// 首个命中生效、末尾 default 兜底。无则退回每口 outbound: 静态绑定。
	// relay 多跳/dialerProxy:全部出站建好后接线 dialer 链(设 BaseDial)+ 环检测
	if err := wireDialers(f.Outbounds, outs); err != nil {
		return nil, err
	}
	var router *service.RuleRouter
	if f.Routing != nil {
		eng, err := buildRouter(ctx, f.Routing, outs)
		if err != nil {
			return nil, err
		}
		router = &service.RuleRouter{Engine: eng, Outs: outs}
		if dnsResolver != nil { // fake-ip 反查:伪 IP dst 路由前换回域名(未启用 fake-ip 时 FakeIPToDomain 恒 false,无害)
			router.Fake = dnsResolver.FakeIPToDomain
		}
		if eng.HasProcess() { // 有 process 规则才装进程反查器(读 /proc,仅 Linux;其他平台优雅降级不命中)
			router.Finder = service.NewProcessFinder()
		}
	}

	var insts []Instance
	// 策略组的后台健康探测循环(urltest/fallback/load-balance)挂成无监听 Instance(同 bridge/metrics)。
	for _, g := range groupLoops {
		g := g
		insts = append(insts, Instance{Listen: "group:" + g.Name(), Run: g.HealthLoop})
	}
	// 第4章:顶层 users 脱糖成各口 CredBinding(纯函数,见 desugar.go)。口名缺省 listen 兜底;
	// 认证协议 = 栈顶协议名(单层;多层待骨头 4)。canonical 留到每口建栈后(那时 CredentialCodec 才可用)。
	inboundNames := make(map[string]bool, len(f.Inbounds))
	stackProtos := make(map[string][]string, len(f.Inbounds))
	for i := range f.Inbounds {
		if f.Inbounds[i].newFormat() && f.Inbounds[i].Name == "" {
			// 新格式口是凭据/计费的锚点(users.on 引用它、BillID 以它为后缀),身份必须稳定,不能靠监听地址兜底
			return nil, fmt.Errorf("config: 入站 #%d(type %q)是第4章新格式,必须写 name (E-INBOUND-NONAME)", i, f.Inbounds[i].Type)
		}
		name := f.Inbounds[i].inboundName()
		if name == "" {
			continue // 无 listen 无 name 的口(tun):不进凭据体系
		}
		if inboundNames[name] {
			return nil, fmt.Errorf("config: 入站口名重复 %q (E-INBOUND-DUP)", name)
		}
		inboundNames[name] = true
		if p := f.Inbounds[i].authProto(); p != "" {
			stackProtos[name] = []string{p}
		}
	}
	bindings, err := Desugar(f.Users, inboundNames, stackProtos)
	if err != nil {
		return nil, err
	}
	if metricReg == nil { // per-user 限额挂在计量子系统上;metrics 未开时限额会静默失效 → 判死(冻结律#6)
		for _, b := range bindings {
			if b.Limit != nil {
				return nil, fmt.Errorf("config: user %q 配了 rate/max-conns/max-ips 但未启用 metrics:(per-user 限额依赖计量子系统;请加 metrics: 块或去掉限额)", b.Name)
			}
		}
	}
	bindingsByInbound := make(map[string][]principal.CredBinding, len(bindings))
	for _, b := range bindings {
		bindingsByInbound[b.Inbound] = append(bindingsByInbound[b.Inbound], b)
	}

	for i, in := range f.Inbounds {
		in.Listen = in.listenAddr()              // 第4章 listen(host)+port 合成;旧格式 host:port 原样
		if in.Listen == "" && in.Type != "tun" { // tun 无监听端口,靠接口名
			return nil, fmt.Errorf("config: 入站 #%d 缺 listen", i)
		}
		outName := in.Outbound
		if outName == "" {
			outName = "direct"
		}
		out, ok := outs[outName]
		if !ok {
			return nil, fmt.Errorf("config: 入站 %s 引用了未定义的出站 %q", in.Listen, outName)
		}
		// 出站解析器:有 routing: 块 → 规则引擎按目标分流(首个命中);否则退回每口静态绑定。
		var resolver service.OutboundResolver = service.StaticOutbound{Out: out}
		if router != nil {
			resolver = router
			// 会话式 / TUN / tproxy / redirect / tunnel 持 endpoint.Outbound(非 resolver),
			// 用适配器让它们也经规则引擎分流 + fake-ip 反查(TUN/tproxy 只见 IP 的流量按域名分流)。
			out = service.NewResolverOutbound(router)
		}

		typ := in.Type
		if in.newFormat() { // 第4章新格式:type=协议名(vless/trojan/snell…)+ 层块,走流式栈(同 proxy 形态)
			typ = "proxy"
		}
		binds := bindingsByInbound[in.inboundName()] // 该口的顶层 users 脱糖产物(proxy/portal 共用)
		var handler endpoint.InboundHandler
		switch typ {
		case "", "proxy":
			h, base, err := f.buildProxyInbound(ctx, in, resolver, binds, reg, metricReg != nil)
			if err != nil {
				return nil, err
			}
			if base != nil { // UDP-base(mkcp):自管 UDP 监听 + KCP accept,accept 出的流交 HandleStream
				listen := in.Listen
				insts = append(insts, Instance{Listen: listen, Run: func(ctx context.Context) error {
					ln, err := base.ListenBase(ctx, listen)
					if err != nil {
						return err
					}
					return service.ServeBase(ctx, ln, h)
				}})
				continue
			}
			handler = h
		case "portal":
			// 反向代理 Portal:复用普通代理入站建栈 + 注册用户,再包成 reverse.Portal
			// (control-domain 区分 Bridge 控制连接与用户连接)。out 未用(Portal 覆盖 HandleStream)。
			pin, _, err := f.buildProxyInbound(ctx, in, resolver, binds, reg, metricReg != nil)
			if err != nil {
				return nil, err
			}
			handler = &reverse.Portal{HS: pin, Control: in.ControlDomain}
		case "anytls":
			h, err := buildAnytlsInbound(in, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(anytls):%w", in.Listen, err)
			}
			handler = h
		case "ssh":
			h, err := buildSshInbound(in, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(ssh):%w", in.Listen, err)
			}
			handler = h
		case "trusttunnel":
			h, err := buildTrusttunnelInbound(in, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(trusttunnel):%w", in.Listen, err)
			}
			handler = h
		case "naive":
			h, err := buildNaiveInbound(in, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(naive):%w", in.Listen, err)
			}
			handler = h
		case "hysteria1":
			inb, err := buildHy1Inbound(in, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(hysteria1):%w", in.Listen, err)
			}
			listen := in.Listen
			insts = append(insts, Instance{Listen: listen, Run: func(ctx context.Context) error { return inb.Run(ctx, listen) }})
			continue
		case "hysteria2":
			inb, err := buildHy2Inbound(in, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(hysteria2):%w", in.Listen, err)
			}
			listen := in.Listen
			insts = append(insts, Instance{Listen: listen, Run: func(ctx context.Context) error { return inb.Run(ctx, listen) }})
			continue
		case "tuic":
			inb, err := buildTuicInbound(in, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(tuic):%w", in.Listen, err)
			}
			listen := in.Listen
			insts = append(insts, Instance{Listen: listen, Run: func(ctx context.Context) error { return inb.Run(ctx, listen) }})
			continue
		case "shadowquic":
			inb, err := buildShadowquicInbound(in, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(shadowquic):%w", in.Listen, err)
			}
			listen := in.Listen
			insts = append(insts, Instance{Listen: listen, Run: func(ctx context.Context) error { return inb.Run(ctx, listen) }})
			continue
		case "mieru":
			inb, err := buildMieruInbound(in, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(mieru):%w", in.Listen, err)
			}
			listen := in.Listen
			insts = append(insts, Instance{Listen: listen, Run: func(ctx context.Context) error { return inb.Run(ctx, listen) }})
			continue
		case "connect-ip":
			inb, err := buildConnectIPInbound(in, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(connect-ip):%w", in.Listen, err)
			}
			listen := in.Listen
			insts = append(insts, Instance{Listen: listen, Run: func(ctx context.Context) error { return inb.Run(ctx, listen) }})
			continue
		case "dns":
			if dnsResolver == nil {
				return nil, fmt.Errorf("config: 入站 %s(dns)需启用 dns:(dns.enabled=true 提供 resolver)", in.Listen)
			}
			srv := dnsin.New(dnsResolver)
			listen := in.Listen
			insts = append(insts, Instance{Listen: listen, Run: func(ctx context.Context) error { return srv.Run(ctx, listen) }})
			continue
		case "tun":
			hijack, herr := parseHijack(in.DNSHijack)
			if herr != nil {
				return nil, fmt.Errorf("config: 入站 tun dns-hijack:%w", herr)
			}
			if len(hijack) > 0 && dnsResolver == nil {
				return nil, fmt.Errorf("config: 入站 tun 用了 dns-hijack,但未启用 dns:(需 dns.enabled=true 提供 resolver)")
			}
			inb, err := tun.NewInbound(tun.Options{Name: in.IfName, Address: in.Address, MTU: in.MTU, Resolver: dnsResolver, HijackDNS: hijack, AutoRoute: in.AutoRoute, RouteExclude: in.RouteExclude}, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 tun:%w", err)
			}
			insts = append(insts, Instance{Listen: "tun:" + in.IfName, Run: func(ctx context.Context) error { return inb.Run(ctx, "") }})
			continue
		case "tunnel":
			inb, err := tunnel.NewInbound(tunnel.Options{Target: in.Target, Network: in.Network}, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(tunnel):%w", in.Listen, err)
			}
			listen := in.Listen
			insts = append(insts, Instance{Listen: listen, Run: func(ctx context.Context) error { return inb.Run(ctx, listen) }})
			continue
		case "redirect", "tproxy":
			inb, err := transparent.NewInbound(transparent.Options{Mode: in.Type, Network: in.Network}, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(%s):%w", in.Listen, in.Type, err)
			}
			listen := in.Listen
			insts = append(insts, Instance{Listen: listen, Run: func(ctx context.Context) error { return inb.Run(ctx, listen) }})
			continue
		case "masque":
			inb, err := buildMasqueInbound(in, out)
			if err != nil {
				return nil, fmt.Errorf("config: 入站 %s(masque):%w", in.Listen, err)
			}
			listen := in.Listen
			insts = append(insts, Instance{Listen: listen, Run: func(ctx context.Context) error { return inb.Run(ctx, listen) }})
			continue
		default:
			return nil, fmt.Errorf("config: 入站 %s 未知 type %q", in.Listen, in.Type)
		}
		// 全局 + 每口连接闸(§6.2 层1/2):建每口闸,叠成 [全局, 口] 挂到 ProxyInbound。
		inboundGate, err := buildGate(in.Limits)
		if err != nil {
			return nil, fmt.Errorf("config: 入站 %s(limits):%w", in.Listen, err)
		}
		gates := nonNilGates(globalGate, inboundGate)
		if pi := asProxyInbound(handler); pi != nil {
			pi.Gates = gates
			if metricReg != nil { // 按用户计量;每用户限额已在 buildProxyInbound 装配凭据时同处挂载
				pi.Meter = metricReg
			}
		}
		insts = append(insts, Instance{Listen: in.Listen, Handler: handler})
	}

	// 顶层 users 的限额【按人合计】(§4.5.1 LimitRef:一个 user 一个单元,其名下各口凭据共指):
	// 同一 user 的所有 BillID 挂到同一个共享限流单元 —— rate/max-ips/max-conns 是合计,不是每口各一份。
	if metricReg != nil {
		byUser := make(map[string][]cred.ID)
		limits := make(map[string]*principal.LimitRef)
		for _, b := range bindings {
			if b.Limit == nil {
				continue
			}
			byUser[b.Name] = append(byUser[b.Name], metricReg.IDForBill(b.BillID))
			limits[b.Name] = b.Limit
		}
		for name, ids := range byUser {
			l := limits[name]
			metricReg.SetLimitsShared(ids, meter.Limits{MaxConns: int64(l.MaxConns), Rate: float64(l.Rate), MaxIPs: int(l.MaxIPs)})
		}
	}

	// 给源自 inbound 的 Instance 打源配置语义哈希(热重载 diff:同 Listen 但 Hash 变 = 重启该口)。
	inboundHash := make(map[string]string, len(f.Inbounds))
	for _, in := range f.Inbounds {
		key := in.Listen
		if in.Type == "tun" {
			key = "tun:" + in.IfName
		}
		inboundHash[key] = hashOf(in)
	}
	for i := range insts {
		if h, ok := inboundHash[insts[i].Listen]; ok {
			insts[i].Hash = h
		}
	}

	// 反向代理 Bridge:主动拨 Portal 建隧道(无监听,自跑 Run 直到 ctx 取消)。
	for i, b := range f.Bridges {
		if b.Portal == "" {
			return nil, fmt.Errorf("config: bridge #%d 缺 portal(拨 Portal 的出站名)", i)
		}
		out, ok := outs[b.Portal]
		if !ok {
			return nil, fmt.Errorf("config: bridge #%d 引用未定义出站 %q", i, b.Portal)
		}
		control := b.ControlDomain
		if control == "" {
			control = reverse.DefaultControlDomain
		}
		br := &reverse.Bridge{
			Dial:    out, // endpoint.Outbound 满足 reverse.StreamDialer
			Control: addr.FromFqdn(control, 0),
			Dialer:  net.Dialer{Timeout: 10 * time.Second}, // 落地拨号超时,防黑洞目标挂死 land goroutine
			Pool:    b.Pool,
		}
		label := fmt.Sprintf("reverse-bridge#%d→%s", i, b.Portal)
		insts = append(insts, Instance{Listen: label, Hash: hashOf(b), Run: br.Run})
	}

	// 计量/控制 HTTP 端点(开启时):默认仅本机可访问,access 白名单显式放开。
	if metricReg != nil {
		listen := f.Metrics.Listen
		allow, err := parseAccess(f.Metrics.Access)
		if err != nil {
			return nil, fmt.Errorf("config: metrics.access:%w", err)
		}
		insts = append(insts, Instance{Listen: "metrics:" + listen, Hash: hashOf(f.Metrics), Run: func(ctx context.Context) error {
			return serveMetrics(ctx, listen, metricReg, allow)
		}})
	}

	if len(insts) == 0 {
		return nil, fmt.Errorf("config: 无 inbounds / bridges")
	}
	return insts, nil
}

// serveMetrics 起计量 + 热开关 HTTP 端点。阻塞至 ctx 取消。
//
//	GET  /stats               每用户 up/down/连接数/停用态 JSON
//	POST /disable?id=<credID> 停用凭据(拒新 + 断老,承 §6.5);回执 {"killed":N}
//	POST /enable?id=<credID>  恢复凭据
//	POST /kill?conn=<connID>  断单条连接;回执 {"killed":0|1}
func serveMetrics(ctx context.Context, listen string, reg *meter.Registry, allow []netip.Prefix) error {
	// gate:按客户端源 IP 过白名单;不在则 403(即便 listen 绑 0.0.0.0 也只放白名单)。
	gate := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !accessAllowed(r.RemoteAddr, allow) {
				http.Error(w, "forbidden (metrics.access)", http.StatusForbidden)
				return
			}
			h(w, r)
		}
	}
	writeKilled := func(w http.ResponseWriter, killed int) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"killed": killed})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", gate(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reg.Snapshot())
	}))
	// 凭据定位:优先稳定身份 bill=name@inbound(面板对账用);兼容数字 id=。
	credID := func(req *http.Request) (cred.ID, bool) {
		q := req.URL.Query()
		if b := q.Get("bill"); b != "" {
			return reg.IDByBill(b)
		}
		id, err := parseUint(q.Get("id"))
		return cred.ID(id), err == nil
	}
	mux.HandleFunc("/disable", gate(func(w http.ResponseWriter, req *http.Request) {
		id, ok := credID(req)
		if !ok {
			http.Error(w, "bad id/bill", http.StatusBadRequest)
			return
		}
		killed, ok := reg.Disable(id)
		if !ok {
			http.Error(w, "no such cred", http.StatusNotFound)
			return
		}
		writeKilled(w, killed)
	}))
	mux.HandleFunc("/enable", gate(func(w http.ResponseWriter, req *http.Request) {
		id, ok := credID(req)
		if !ok {
			http.Error(w, "bad id/bill", http.StatusBadRequest)
			return
		}
		if !reg.Enable(id) {
			http.Error(w, "no such cred", http.StatusNotFound)
			return
		}
		writeKilled(w, 0)
	}))
	mux.HandleFunc("/kill", gate(func(w http.ResponseWriter, req *http.Request) {
		connID, err := parseUint(req.URL.Query().Get("conn"))
		if err != nil {
			http.Error(w, "bad conn", http.StatusBadRequest)
			return
		}
		writeKilled(w, reg.KillConn(connID))
	}))
	srv := &http.Server{Addr: listen, Handler: mux}
	context.AfterFunc(ctx, func() { _ = srv.Close() })
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return ctx.Err()
	}
	return err
}

// parseUint 解析十进制无符号整数(计量控制端点的 id/conn 参数)。
func parseUint(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }

// nonNilGates 把若干闸滤掉 nil,叠成有序切片(全局在前、口在后)。
func nonNilGates(gs ...*meter.Gate) []*meter.Gate {
	var out []*meter.Gate
	for _, g := range gs {
		if g != nil {
			out = append(out, g)
		}
	}
	return out
}

// asProxyInbound 从 handler 取出底层 ProxyInbound(直接 或 reverse.Portal 包裹的);否则 nil。
func asProxyInbound(handler endpoint.InboundHandler) *service.ProxyInbound {
	if pi, ok := handler.(*service.ProxyInbound); ok {
		return pi
	}
	if pt, ok := handler.(*reverse.Portal); ok {
		if pi, ok := pt.HS.(*service.ProxyInbound); ok {
			return pi
		}
	}
	return nil
}

// buildGate 从一层 LimitsSpec 建 meter.Gate(全局/每口;无限制返回 nil)。
func buildGate(l *LimitsSpec) (*meter.Gate, error) {
	if l == nil {
		return nil, nil
	}
	var rate float64
	if l.Rate != "" {
		r, err := parseRate(l.Rate)
		if err != nil {
			return nil, err
		}
		rate = r
	}
	return meter.NewGate(l.MaxConns, rate), nil
}

// parseUserLimits 从用户配置 map 解出 max-conns / rate / max-ips(承 §6.2)。ok=false 表示无任何限额。
func parseUserLimits(u map[string]any) (meter.Limits, bool) {
	var l meter.Limits
	has := false
	if v, ok := toInt(u["max-conns"]); ok && v > 0 {
		l.MaxConns = int64(v)
		has = true
	}
	if v, ok := toInt(u["max-ips"]); ok && v > 0 {
		l.MaxIPs = v
		has = true
	}
	if s, ok := u["rate"].(string); ok && s != "" {
		if bps, err := parseRate(s); err == nil && bps > 0 {
			l.Rate = bps
			has = true
		}
	}
	return l, has
}

// toInt 把 YAML 解出的数值(int/int64/float64)归一成 int。
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

// parseRate 解析速率("500mbps"/"50kbps"/"2gbps"/"1000bps"/裸数字=bps)→ 字节/秒。
func parseRate(s string) (float64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mult := 1.0 // bits per unit
	switch {
	case strings.HasSuffix(s, "gbps"):
		mult, s = 1e9, strings.TrimSuffix(s, "gbps")
	case strings.HasSuffix(s, "mbps"):
		mult, s = 1e6, strings.TrimSuffix(s, "mbps")
	case strings.HasSuffix(s, "kbps"):
		mult, s = 1e3, strings.TrimSuffix(s, "kbps")
	case strings.HasSuffix(s, "bps"):
		mult, s = 1, strings.TrimSuffix(s, "bps")
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("config: 速率非法 %q", s)
	}
	return n * mult / 8, nil // bits/s → bytes/s
}

// hashOf 取任意配置值的语义哈希(YAML 规范序列化 + SHA256),供热重载 diff。
func hashOf(v any) string {
	b, _ := yaml.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// parseAccess 把 access 白名单解析成前缀集。空 → 仅本机(127.0.0.0/8 + ::1/128)。
// 每项可为 CIDR("10.0.0.0/8")或单 IP("192.168.1.5" → /32 或 /128)。
func parseAccess(access []string) ([]netip.Prefix, error) {
	if len(access) == 0 {
		return []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
		}, nil
	}
	var out []netip.Prefix
	for _, a := range access {
		a = strings.TrimSpace(a)
		if p, err := netip.ParsePrefix(a); err == nil {
			out = append(out, p)
			continue
		}
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("非法条目 %q(需 IP 或 CIDR)", a)
		}
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out, nil
}

// accessAllowed 判 remoteAddr(host:port)的源 IP 是否命中白名单前缀。
func accessAllowed(remoteAddr string, allow []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// buildProxyInbound 建流式栈入站(BuildInbound + 注册凭据)。凭据来源二选一:顶层 users 脱糖的
// bindings(第4章,优先);无则退回旧口内 in.Users(兼容垫片,脚本迁完即拆)。
// 数字句柄一律经 reg.IDForBill 分配(顶层 users 用 BillID;垫片用 "<口>#<序号>" 合成 bill),两条路径
// 不再各算一套 id、跨 reload 稳定。顶层 users 的【按人合计】限额在 Build 末尾统一挂(见 applyUserLimits);
// 垫片的每口限额仍在此处逐条设(metering 关闭而配了限额 → fail-loud)。
func (f *File) buildProxyInbound(ctx context.Context, in Inbound, resolver service.OutboundResolver, bindings []principal.CredBinding, reg *meter.Registry, metering bool) (*service.ProxyInbound, transport.BaseTransport, error) {
	layers, err := in.synthLayers() // 旧 layers 数组(垫片)或第4章 type=协议名+层块
	if err != nil {
		return nil, nil, fmt.Errorf("config: 入站 %s:%w", in.inboundName(), err)
	}
	auth := service.NewStaticAuth()
	handler, base, err := service.BuildInbound(ctx, layers, auth, resolver)
	if err != nil {
		return nil, nil, fmt.Errorf("config: 入站 %s:%w", in.Listen, err)
	}
	handler.Fallback = in.Fallback // 回落伪装站(空=不开)
	handler.Sniff = in.Sniff       // 域名嗅探(false=不开;IP 目标 peek 首包 SNI/Host 解真域名再分流)
	for _, r := range in.Fallbacks {
		handler.Fallbacks = append(handler.Fallbacks, service.FallbackRule{SNI: r.SNI, ALPN: r.ALPN, Path: r.Path, Dest: r.Dest, Xver: r.Xver})
	}
	cc, hasCodec := handler.Proxy.(proxy.CredentialCodec)
	if !hasCodec {
		if len(bindings) > 0 { // 配了顶层 users 却接不上:fail-loud,绝不静默落 Ambient(冻结律#6)
			return nil, nil, fmt.Errorf("config: 入站 %s 配了 users 但协议 %q 不支持 per-user 凭据 (E-USERS-NO-CODEC)", in.inboundName(), layers[len(layers)-1].Name)
		}
		return handler, base, nil // 协议无 per-user 凭据且未配 users(socks no-auth / mixed …):不登记、不设限
	}
	// 鉴权可选的协议(socks/http/gost):登记完凭据后告知"本口是否配了凭据"(能力发现,零协议 switch)
	gate := func(registered int) {
		if g, ok := handler.Proxy.(proxy.AuthGate); ok {
			g.SetAuthRequired(registered > 0)
		}
	}
	if len(bindings) > 0 {
		// 第4章路径:每条 binding 每层 canonical(AuthKey)后登记;id 由 reg.IDForBill(BillID) 给,同 BillID
		// (轮换平行 binding)自然共享。canonical 键撞车(两个 principal 派生出同一鉴权键)在 Desugar 的
		// E-KEY-DUP 之外再兜一层:auth 表已有该键且指向别的 id → 判死,绝不静默覆盖。
		defer gate(len(bindings))
		for _, b := range bindings {
			id := reg.IDForBill(b.BillID)
			for _, layer := range b.Layers { // 当前单层(栈顶);多层待传输层参与 auth(骨头 4)
				key, err := cc.AuthKey(string(layer.Key))
				if err != nil {
					return nil, nil, fmt.Errorf("config: 入站 %s 凭据 %s:%w", in.inboundName(), b.BillID, err)
				}
				if prev, dup := auth.Auth(layer.Scheme, key); dup && prev.ID != id {
					return nil, nil, fmt.Errorf("config: 入站 %s 凭据 %s 与 %s 派生出同一鉴权键 (E-KEY-DUP)", in.inboundName(), b.BillID, reg.Bill(prev.ID))
				}
				auth.Add(layer.Scheme, key, cred.Ref{ID: id})
			}
		}
		return handler, base, nil
	}
	// 兼容垫片:旧口内 users(身份 = UserBase+j+1,跨口会撞——正是第4章要修的;脚本迁完拆)
	scheme := layers[len(layers)-1].Name
	registered := 0
	for j, u := range in.Users {
		secret := userSecret(u)
		if secret == "" {
			continue
		}
		key, err := cc.AuthKey(secret)
		if err != nil {
			return nil, nil, fmt.Errorf("config: 入站 %s 用户 #%d:%w", in.Listen, j, err)
		}
		id := reg.IDForBill(in.inboundName() + "#" + strconv.Itoa(j)) // 垫片合成 bill:与顶层 users 同一分配器,不撞、跨 reload 稳定
		auth.Add(scheme, key, cred.Ref{ID: id})
		registered++
		if lim, ok := parseUserLimits(u); ok {
			if !metering {
				return nil, nil, fmt.Errorf("config: 入站 %s 用户 #%d 配了限额但未启用 metrics:(限额会静默失效)", in.Listen, j)
			}
			reg.SetLimits(id, lim)
		}
	}
	gate(registered)
	return handler, base, nil
}

// buildAnytlsInbound 建 AnyTLS 会话入站(TLS 证书 + 用户 + 绑定出站)。
func buildAnytlsInbound(in Inbound, out endpoint.Outbound) (endpoint.InboundHandler, error) {
	certPEM := fileOrStr(in.TLS, "cert")
	keyPEM := fileOrStr(in.TLS, "key")
	tlsConfig, err := anytls.ServerTLSConfig(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	var users []anytls.User
	for _, u := range in.Users {
		pw, _ := u["password"].(string)
		if pw == "" {
			continue
		}
		name, _ := u["name"].(string)
		users = append(users, anytls.User{Name: name, Password: pw})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("anytls 入站需至少一个 user{password}")
	}
	return anytls.NewInbound(users, tlsConfig, out, sessionPortalDispatch(in))
}

// buildSshInbound 建 SSH 会话入站(host 私钥 = tls.key + 用户{password/public-key} + 绑定出站)。
func buildSshInbound(in Inbound, out endpoint.Outbound) (*sshproto.Inbound, error) {
	hostKey := fileOrStr(in.TLS, "key")
	if hostKey == "" {
		return nil, fmt.Errorf("ssh 入站需 tls.key(host 私钥 PEM)")
	}
	var users []sshproto.User
	for _, u := range in.Users {
		name, _ := u["name"].(string)
		pw, _ := u["password"].(string)
		pk, _ := u["public-key"].(string)
		if pw == "" && pk == "" {
			continue
		}
		users = append(users, sshproto.User{Name: name, Password: pw, PublicKey: pk})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("ssh 入站需至少一个 user{password 或 public-key}")
	}
	return sshproto.NewInbound(users, hostKey, out, sessionPortalDispatch(in))
}

// buildTrusttunnelInbound 建 TrustTunnel 会话入站(服务端证书 = tls.cert/key + Basic 用户 + 绑定出站)。
func buildTrusttunnelInbound(in Inbound, out endpoint.Outbound) (*trusttunnel.Inbound, error) {
	tlsConfig, err := anytls.ServerTLSConfig(fileOrStr(in.TLS, "cert"), fileOrStr(in.TLS, "key"))
	if err != nil {
		return nil, err
	}
	var users []trusttunnel.User
	for _, u := range in.Users {
		name, _ := u["name"].(string)
		pw, _ := u["password"].(string)
		if name == "" {
			continue
		}
		users = append(users, trusttunnel.User{Name: name, Password: pw})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("trusttunnel 入站需至少一个 user{name,password}")
	}
	return trusttunnel.NewInbound(users, tlsConfig, out, sessionPortalDispatch(in))
}

// buildNaiveInbound 建 NaiveProxy 会话入站(服务端证书 = tls.cert/key + Basic 用户 + 绑定出站)。
func buildNaiveInbound(in Inbound, out endpoint.Outbound) (*naive.Inbound, error) {
	tlsConfig, err := anytls.ServerTLSConfig(fileOrStr(in.TLS, "cert"), fileOrStr(in.TLS, "key"))
	if err != nil {
		return nil, err
	}
	var users []naive.User
	for _, u := range in.Users {
		name, _ := u["name"].(string)
		pw, _ := u["password"].(string)
		if name == "" {
			continue
		}
		users = append(users, naive.User{Name: name, Password: pw})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("naive 入站需至少一个 user{name,password}")
	}
	return naive.NewInbound(users, tlsConfig, out, sessionPortalDispatch(in))
}

// buildConnectIPInbound 建 CONNECT-IP 入站(QUIC/h3 证书 + 下发地址 + 绑定出站)。
func buildConnectIPInbound(in Inbound, out endpoint.Outbound) (*connectip.Inbound, error) {
	tlsConfig, err := hysteria2.ServerTLSConfig(fileOrStr(in.TLS, "cert"), fileOrStr(in.TLS, "key"))
	if err != nil {
		return nil, err
	}
	return connectip.NewInbound(connectip.InboundOptions{
		AssignAddress: in.AssignAddress,
		MTU:           in.MTU,
	}, tlsConfig, out)
}

// buildMasqueInbound 建 MASQUE 会话入站(QUIC/h3 证书 + 可选 Basic 用户 + 绑定出站)。
// 用户可为空 = 不鉴权(MASQUE 本身无标准认证层)。
func buildMasqueInbound(in Inbound, out endpoint.Outbound) (*masque.Inbound, error) {
	tlsConfig, err := hysteria2.ServerTLSConfig(fileOrStr(in.TLS, "cert"), fileOrStr(in.TLS, "key"))
	if err != nil {
		return nil, err
	}
	var users []masque.User
	for _, u := range in.Users {
		name, _ := u["name"].(string)
		pw, _ := u["password"].(string)
		if name == "" {
			continue
		}
		users = append(users, masque.User{Name: name, Password: pw})
	}
	return masque.NewInbound(users, tlsConfig, out, sessionPortalDispatch(in))
}

// buildHy2Inbound 建 Hysteria2 会话入站(metacubex-tls 证书 + 用户 + 绑定出站)。
func buildHy1Inbound(in Inbound, out endpoint.Outbound) (*hysteria1.Inbound, error) {
	tlsConfig, err := anytls.ServerTLSConfig(fileOrStr(in.TLS, "cert"), fileOrStr(in.TLS, "key"))
	if err != nil {
		return nil, err
	}
	var users []hysteria1.User
	for _, u := range in.Users {
		pw, _ := u["password"].(string)
		if pw == "" {
			continue
		}
		users = append(users, hysteria1.User{Password: pw})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("hysteria1 入站需至少一个 user{password}")
	}
	return hysteria1.NewInbound(users, in.Obfs, 0, 0, tlsConfig, out, sessionPortalDispatch(in))
}

func buildHy2Inbound(in Inbound, out endpoint.Outbound) (*hysteria2.Inbound, error) {
	tlsConfig, err := hysteria2.ServerTLSConfig(fileOrStr(in.TLS, "cert"), fileOrStr(in.TLS, "key"))
	if err != nil {
		return nil, err
	}
	var users []hysteria2.User
	for _, u := range in.Users {
		pw, _ := u["password"].(string)
		if pw == "" {
			continue
		}
		name, _ := u["name"].(string)
		users = append(users, hysteria2.User{Name: name, Password: pw})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("hysteria2 入站需至少一个 user{password}")
	}
	return hysteria2.NewInbound(users, tlsConfig, in.Obfs, out, sessionPortalDispatch(in))
}

// buildMieruInbound 建 mieru 会话入站(官方库自绑端口,用户名+口令,TCP/UDP 传输)。
func buildMieruInbound(in Inbound, out endpoint.Outbound) (*mieru.Inbound, error) {
	var users []mieru.User
	for _, u := range in.Users {
		name, _ := u["name"].(string)
		pw, _ := u["password"].(string)
		if name == "" || pw == "" {
			continue
		}
		users = append(users, mieru.User{Name: name, Password: pw})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("mieru 入站需至少一个 user{name,password}")
	}
	return mieru.NewInbound(users, in.Transport, out, sessionPortalDispatch(in))
}

// buildTuicInbound 建 TUIC 会话入站(证书 + UUID/password 用户 + 绑定出站)。
func buildTuicInbound(in Inbound, out endpoint.Outbound) (*tuic.Inbound, error) {
	tlsConfig, err := anytls.ServerTLSConfig(fileOrStr(in.TLS, "cert"), fileOrStr(in.TLS, "key"))
	if err != nil {
		return nil, err
	}
	var users []tuic.User
	for _, u := range in.Users {
		uuid, _ := u["uuid"].(string)
		pw, _ := u["password"].(string)
		if uuid == "" {
			continue
		}
		users = append(users, tuic.User{UUID: uuid, Password: pw})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("tuic 入站需至少一个 user{uuid,password}")
	}
	return tuic.NewInbound(users, tlsConfig, out, sessionPortalDispatch(in))
}

// buildShadowquicInbound 建 ShadowQUIC 入站(JLS PSK 用户 + sni)。sni 从 tls.sni 取(JLS ServerName,
// 须与客户端 servername 一致);dest 兜底 sni(v1 无回落 relay,dest 仅供 sni 推导)。
func buildShadowquicInbound(in Inbound, out endpoint.Outbound) (*shadowquic.Inbound, error) {
	var users []shadowquic.User
	for _, u := range in.Users {
		un, _ := u["username"].(string)
		pw, _ := u["password"].(string)
		if un == "" {
			continue
		}
		users = append(users, shadowquic.User{Username: un, Password: pw})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("shadowquic 入站需至少一个 user{username,password}")
	}
	return shadowquic.NewInbound(users, fileOrStr(in.TLS, "sni"), in.Target, nil, out, sessionPortalDispatch(in))
}

// sessionPortalDispatch:会话式协议(anytls/hy1/hy2/tuic —— 自管监听、每流已握手)作 reverse portal
// 时的每流派发。in.ControlDomain 非空 → 建一个 Portal(隧道池)并返回其 Dispatch 适配(会话式反连
// UDP 后置,传 nil);否则 nil(走默认 relay 到出站)。★协议本身一行不改,只在此接线注入。
func sessionPortalDispatch(in Inbound) endpoint.StreamDispatch {
	if in.ControlDomain == "" {
		return nil
	}
	portal := &reverse.Portal{Control: in.ControlDomain}
	return func(ctx context.Context, s link.Stream, dst addr.Socksaddr, network endpoint.Network) error {
		return portal.Dispatch(ctx, s, dst, network, nil)
	}
}

// fileOrStr 从 tls 子映射取 key 的内容:支持 `key`(内联 PEM)或 `key-file`(读文件)。
func fileOrStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok && s != "" {
		return s
	}
	if p, ok := m[key+"-file"].(string); ok && p != "" {
		if b, err := os.ReadFile(p); err == nil {
			return string(b)
		}
	}
	return ""
}

// toLayerSpecs 把 YAML 层列表转成 service.LayerSpec(type→注册表名,其余键→spec.Node)。
func toLayerSpecs(layers []map[string]any) ([]service.LayerSpec, error) {
	if len(layers) == 0 {
		return nil, fmt.Errorf("layers 为空")
	}
	specs := make([]service.LayerSpec, 0, len(layers))
	for _, l := range layers {
		typ, _ := l["type"].(string)
		if typ == "" {
			return nil, fmt.Errorf("某层缺 type")
		}
		node, err := mapToNode(l, "type")
		if err != nil {
			return nil, fmt.Errorf("层 %q:%w", typ, err)
		}
		specs = append(specs, service.LayerSpec{Name: typ, Node: node})
	}
	return specs, nil
}

// mapToNode 把配置 map 转成 spec 映射节点(排除 skip 键;`xxx-file` 键读文件注入到 `xxx`)。
func mapToNode(m map[string]any, skip string) (*spec.Node, error) {
	out := make(map[string]*spec.Node, len(m))
	for k, v := range m {
		if k == skip {
			continue
		}
		if name, ok := strings.CutSuffix(k, "-file"); ok {
			path, _ := v.(string)
			b, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("读取 %s(键 %s)失败:%w", path, k, err)
			}
			out[name] = spec.Scalar(string(b))
			continue
		}
		out[k] = valueToNode(v)
	}
	return &spec.Node{Kind: spec.KindMap, Map: out}, nil
}

// valueToNode 把任意 YAML 值递归转成 spec.Node(标量统一转字符串)。
func valueToNode(v any) *spec.Node {
	switch t := v.(type) {
	case nil:
		return &spec.Node{Kind: spec.KindNull}
	case map[string]any:
		m := make(map[string]*spec.Node, len(t))
		for k, val := range t {
			m[k] = valueToNode(val)
		}
		return &spec.Node{Kind: spec.KindMap, Map: m}
	case []any:
		seq := make([]*spec.Node, len(t))
		for i, val := range t {
			seq[i] = valueToNode(val)
		}
		return &spec.Node{Kind: spec.KindSeq, Seq: seq}
	case string:
		return spec.Scalar(t)
	case bool:
		return spec.Scalar(strconv.FormatBool(t))
	case int:
		return spec.Scalar(strconv.Itoa(t))
	case int64:
		return spec.Scalar(strconv.FormatInt(t, 10))
	case float64:
		return spec.Scalar(strconv.FormatFloat(t, 'g', -1, 64))
	default:
		return spec.Scalar(fmt.Sprint(t))
	}
}

// userSecret 从用户项取口令(uuid/password/psk 任一)。
func userSecret(u map[string]any) string {
	for _, k := range []string{"uuid", "password", "psk"} {
		if s, ok := u[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
