// Command ntr 是可运行的代理节点,两模式:
//
//	server:  [tls?→协议] 入站 → 直连出站(收远端客户端)
//	client:  本地 socks 入站 → [tls?→协议] 出站转上游(给本机应用用)
//
// 它是唯一的"组装根",可引用 registry / 具体出站;核心与运行时仍零协议 switch。凭据语义
// 归插件(proxy.CredentialCodec),main 靠能力发现,自身不认协议字段 —— 换协议只改 -protocol。
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/LOVECHEN/ntr/config"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/proxy"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
	_ "github.com/LOVECHEN/ntr/manifest" // 链接进已启用的协议/传输插件(自注册)
	"github.com/LOVECHEN/ntr/meter"
	"github.com/LOVECHEN/ntr/outbound/direct"
	"github.com/LOVECHEN/ntr/service"
)

// runConfig 按 YAML 配置起多入站(声明式部署路径)。支持 SIGHUP 热重载:运行时增删入站(服务/端口
// 上下线)—— 未变的口零断连、删的口停、加的口起、改的口重启(Drain)。承设计 §4.8 两阶段:新配置 Build
// 失败即保留旧配置零扰动;计量注册表跨代复用(累计流量 + metrics 端点不断)。
func runConfig(path string) {
	f, err := config.Load(path)
	if err != nil {
		fatalf("加载配置失败:%v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	insts, err := f.Build(ctx)
	if err != nil {
		fatalf("装配配置失败:%v", err)
	}
	m := &serveManager{root: ctx, active: map[string]*activeInst{}, reg: f.Reg}
	m.apply(insts)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	for {
		select {
		case <-ctx.Done():
			m.stopAll()
			log.Println("ntr: 已优雅关闭")
			return
		case <-hup:
			nf, err := config.Load(path)
			if err != nil {
				log.Printf("ntr: 热重载 —— 加载配置失败,保留旧配置:%v", err)
				continue
			}
			nf.Reg = m.reg // 跨代复用计量注册表
			ninsts, err := nf.Build(ctx)
			if err != nil { // 两阶段:Build 失败即零扰动,继续跑旧配置
				log.Printf("ntr: 热重载 —— 装配失败,保留旧配置:%v", err)
				continue
			}
			m.reg = nf.Reg
			added, removed := m.apply(ninsts)
			log.Printf("ntr: 热重载完成 —— 起 %d 口、停 %d 口、未变的零断连", added, removed)
		}
	}
}

// activeInst 是一个正在跑的 Instance:其 hash(源配置)+ 独立 cancel + 退出信号。
type activeInst struct {
	hash   string
	cancel context.CancelFunc
	done   chan struct{}
}

// serveManager 管理【按 Listen 键】的活跃入站集,支持热重载 diff(起新/停删/重启变更)。
type serveManager struct {
	root   context.Context
	mu     sync.Mutex
	active map[string]*activeInst
	reg    *meter.Registry
}

// apply 把当前活跃集 diff 到目标 insts:同 Listen 且 Hash 未变 → 保留(零断连);Hash 变或已删 → 停;
// 新 Listen → 起。返回 (起了几口, 停了几口)。
func (m *serveManager) apply(insts []config.Instance) (added, removed int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := make(map[string]config.Instance, len(insts))
	for _, in := range insts {
		want[in.Listen] = in
	}
	// 停:已删 或 Hash 变(将重启)。
	for listen, a := range m.active {
		if in, ok := want[listen]; !ok || in.Hash != a.hash {
			a.cancel()
			<-a.done // 等其监听/连接收尾,避免端口重启时抢占
			delete(m.active, listen)
			removed++
		}
	}
	// 起:新的 或 刚被停掉的(重启)。
	for listen, in := range want {
		if _, ok := m.active[listen]; ok {
			continue // 未变,保留
		}
		m.start(in)
		added++
	}
	return added, removed
}

// start 在独立子 ctx 下跑一个 Instance(Run 或 Listen+Serve+UDP),登记进活跃集。
func (m *serveManager) start(inst config.Instance) {
	cctx, cancel := context.WithCancel(m.root)
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveInstance(cctx, inst)
	}()
	m.active[inst.Listen] = &activeInst{hash: inst.Hash, cancel: cancel, done: done}
}

// stopAll 停掉全部活跃入站并等收尾(优雅关闭)。
func (m *serveManager) stopAll() {
	m.mu.Lock()
	all := make([]*activeInst, 0, len(m.active))
	for _, a := range m.active {
		all = append(all, a)
	}
	m.active = map[string]*activeInst{}
	m.mu.Unlock()
	for _, a := range all {
		a.cancel()
	}
	for _, a := range all {
		<-a.done
	}
}

// serveInstance 跑一个 Instance:自管监听(Run)或 TCP 监听 + Serve(+ 原生 UDP)。监听失败只记日志、
// 不 crash(热重载路径要容忍端口占用等瞬时错误,保留其余口)。
func serveInstance(ctx context.Context, inst config.Instance) {
	if inst.Run != nil { // 自管监听的会话式入站(hy2/tuic/tun/tunnel/…)
		log.Printf("ntr: 入站(会话式)监听于 %s", inst.Listen)
		if err := inst.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("ntr: 入站 %s 退出:%v", inst.Listen, err)
		}
		return
	}
	ln, err := net.Listen("tcp", inst.Listen)
	if err != nil {
		log.Printf("ntr: 监听 %s 失败:%v", inst.Listen, err)
		return
	}
	log.Printf("ntr: 入站监听于 %s", ln.Addr())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := service.Serve(ctx, ln, inst.Handler); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("ntr: 入站 %s 退出:%v", ln.Addr(), err)
		}
	}()
	// 原生 UDP 入站(Shadowsocks 等 datagram 协议):与 TCP 同址另开 UDP 监听。
	if np, ok := inst.Handler.(interface {
		SupportsNativePacket() bool
		ServePacket(context.Context, net.PacketConn) error
	}); ok && np.SupportsNativePacket() {
		if upc, err := net.ListenPacket("udp", inst.Listen); err != nil {
			log.Printf("ntr: UDP 监听 %s 失败:%v", inst.Listen, err)
		} else {
			log.Printf("ntr: 入站(原生 UDP)监听于 %s", upc.LocalAddr())
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := np.ServePacket(ctx, upc); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("ntr: UDP 入站 %s 退出:%v", upc.LocalAddr(), err)
				}
			}()
		}
	}
	wg.Wait()
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "report" {
		runReport(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "ech-keygen" {
		runECHKeygen(os.Args[2:])
		return
	}
	configPath := flag.String("config", "", "YAML 配置文件路径(给了则忽略下面的 flags,按配置起多入站)")
	mode := flag.String("mode", "server", "运行模式:server|client")
	listen := flag.String("listen", "127.0.0.1:8388", "监听地址 host:port")
	protocol := flag.String("protocol", "", "代理协议名(snell|vless|trojan|...)")
	server := flag.String("server", "", "client 模式:上游 host:port")
	// 凭据(按协议取其一;语义由插件 CredentialCodec 解释)
	uuid := flag.String("uuid", "", "vless:用户 UUID")
	psk := flag.String("psk", "", "snell:端口 PSK")
	password := flag.String("password", "", "trojan:口令")
	// snell 细项
	snellMode := flag.String("snell-mode", "", "snell:v6 混淆模式(default|unshaped|unsafe-raw)")
	snellVersion := flag.String("snell-version", "", "snell:协议版本 4|5|6(默认 6;4/5 与 mihomo/官方互通)")
	cipher := flag.String("cipher", "", "snell:wire cipher(chacha20-ietf-poly1305)")
	// TLS
	tlsOn := flag.Bool("tls", false, "在协议之下叠一层 TLS")
	tlsCert := flag.String("tls-cert", "", "server TLS:证书 PEM 路径(留空 → 自签临时证书)")
	tlsKey := flag.String("tls-key", "", "server TLS:私钥 PEM 路径")
	tlsSNI := flag.String("tls-sni", "", "client TLS:SNI")
	tlsInsecure := flag.Bool("tls-insecure", false, "client TLS:跳过证书校验(自签上游)")
	// REALITY(与 -tls 互斥,同为 Crypto band)
	realityOn := flag.Bool("reality", false, "在协议之下叠一层 REALITY")
	realityPriv := flag.String("reality-private-key", "", "server REALITY:x25519 私钥(base64/hex)")
	realityPub := flag.String("reality-public-key", "", "client REALITY:服务端 x25519 公钥")
	realityDest := flag.String("reality-dest", "", "server REALITY:借证书/回落的真实站 host:port")
	realitySNI := flag.String("reality-sni", "", "REALITY 借用域名(server 的 server-name / client 的 SNI)")
	realityShortID := flag.String("reality-short-id", "", "REALITY short-id(hex)")
	realityFP := flag.String("reality-fingerprint", "", "client REALITY:uTLS 指纹(chrome/firefox/…)")
	debug := flag.Bool("debug", false, "打印入站握手/处理失败(源+错误);排查连不通用(也可设 NTR_DEBUG=1)")
	flag.Parse()

	if *debug {
		service.SetDebug(true)
	}

	if *configPath != "" {
		runConfig(*configPath)
		return
	}

	if *protocol == "" {
		fatalf("缺少 -protocol;已注册:%s", strings.Join(registeredNames(), ", "))
	}
	if _, ok := registry.Lookup(*protocol); !ok {
		fatalf("未知协议 %q;已注册:%s", *protocol, strings.Join(registeredNames(), ", "))
	}

	protoNode := mapNode(map[string]string{"psk": *psk, "mode": *snellMode, "version": *snellVersion, "cipher": *cipher})
	secret := firstNonEmpty(*uuid, *password, *psk)

	// 加密层(tls / reality,同 band 互斥):两个都开 → compile 定序时报 band 冲突。
	var cryptoLayers []service.LayerSpec
	if *tlsOn {
		cryptoLayers = append(cryptoLayers, service.LayerSpec{Name: "tls", Node: mapNode(map[string]string{
			"cert": readFileOrEmpty(*tlsCert), "key": readFileOrEmpty(*tlsKey),
			"sni": *tlsSNI, "insecure": boolStr(*tlsInsecure),
		})})
	}
	if *realityOn {
		cryptoLayers = append(cryptoLayers, service.LayerSpec{Name: "reality", Node: mapNode(map[string]string{
			"private-key": *realityPriv, "public-key": *realityPub, "dest": *realityDest,
			"server-name": *realitySNI, "short-id": *realityShortID, "fingerprint": *realityFP,
		})})
	}

	ctx := context.Background()
	var handler *service.ProxyInbound
	var desc string

	switch *mode {
	case "server":
		layers := append([]service.LayerSpec{}, cryptoLayers...)
		layers = append(layers, service.LayerSpec{Name: *protocol, Node: protoNode})

		auth := service.NewStaticAuth()
		h, _, err := service.BuildInbound(ctx, layers, auth, service.StaticOutbound{Out: direct.Outbound{}})
		if err != nil {
			fatalf("构建入站栈失败:%v", err)
		}
		// 登记用户:若插件声明凭据编解码,用它派生鉴权键(如 trojan 的 SHA224);否则(snell 端口 PSK)跳过。
		if secret != "" {
			if cc, ok := h.Proxy.(proxy.CredentialCodec); ok {
				key, err := cc.AuthKey(secret)
				if err != nil {
					fatalf("派生鉴权键失败:%v", err)
				}
				auth.Add(*protocol, key, cred.Ref{ID: cred.UserBase + 1})
				log.Printf("ntr: 登记 1 个用户(%s)", *protocol)
			}
		}
		handler = h
		desc = "栈 " + stackDesc(layers) + " → 直连出站"

	case "client":
		if *server == "" {
			fatalf("client 模式需 -server upstream:port")
		}
		outLayers := append([]service.LayerSpec{}, cryptoLayers...)
		outLayers = append(outLayers, service.LayerSpec{Name: *protocol, Node: protoNode})

		out, err := service.BuildOutbound(ctx, *server, outLayers, secret)
		if err != nil {
			fatalf("构建出站栈失败:%v", err)
		}
		h, _, err := service.BuildInbound(ctx,
			[]service.LayerSpec{{Name: "socks", Node: mapNode(nil)}},
			service.NewStaticAuth(),
			service.StaticOutbound{Out: out})
		if err != nil {
			fatalf("构建本地 SOCKS 入站失败:%v", err)
		}
		handler = h
		desc = "本地 socks → 上游 " + *server + "(" + stackDesc(outLayers) + ")"

	default:
		fatalf("未知 -mode %q(server|client)", *mode)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fatalf("监听 %s 失败:%v", *listen, err)
	}
	log.Printf("ntr: %s 监听于 %s", desc, ln.Addr())

	sctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := service.Serve(sctx, ln, handler); err != nil && !errors.Is(err, context.Canceled) {
		fatalf("服务退出:%v", err)
	}
	log.Println("ntr: 已优雅关闭")
}

// readFileOrEmpty 读文件内容(路径空 → 空串;读失败 → 致命)。
func readFileOrEmpty(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fatalf("读取 %s 失败:%v", path, err)
	}
	return string(b)
}

// stackDesc 把层名按书写序(底→顶)拼成 "tls→vless" 样式。
func stackDesc(layers []service.LayerSpec) string {
	names := make([]string, len(layers))
	for i, l := range layers {
		names[i] = l.Name
	}
	return strings.Join(names, "→")
}

// mapNode 把非空键值折成 spec 映射节点。
func mapNode(kv map[string]string) *spec.Node {
	m := make(map[string]*spec.Node, len(kv))
	for k, v := range kv {
		if v != "" {
			m[k] = spec.Scalar(v)
		}
	}
	return &spec.Node{Kind: spec.KindMap, Map: m}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return ""
}

func registeredNames() []string {
	var names []string
	registry.Each(func(d registry.AnyDescriptor) { names = append(names, d.Name()) })
	return names
}

func fatalf(format string, a ...any) {
	log.Printf("ntr: "+format, a...)
	os.Exit(1)
}
