package main

// report 子命令:由 NTR 二进制自省注册表 + 读 CI 互通结果,生成一张自包含 HTML 报告。
// 设计意图:报告由 ntr 自己生成、GitHub Actions 托管发布,不再手写文档、不占本地算力。
// 只报「NTR 自己有什么(注册表事实)」+「跨实现互通跑出来什么(CI 事实)」,不臆造对端能力。

import (
	"flag"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LOVECHEN/ntr/core/cap"
	"github.com/LOVECHEN/ntr/core/registry"

	_ "github.com/LOVECHEN/ntr/manifest" // 触发全部流式栈协议/传输注册(供自省枚举)
)

type pluginRow struct {
	Name, Kind, Band string
	Provides         string
}

type interopRow struct {
	Name, Status string
	Pass, Fail   int
}

func capName(c cap.ID) string {
	switch c {
	case cap.IDSecureCarrier:
		return "SecureCarrier"
	case cap.IDTLSExporter:
		return "TLSExporter"
	case cap.IDVisionCarrier:
		return "VisionCarrier"
	case cap.IDCongestion:
		return "Congestion"
	case cap.IDResettable:
		return "Resettable"
	case cap.IDStreamConn:
		return "StreamConn"
	case cap.IDPacketConn:
		return "PacketConn"
	default:
		return "cap#" + strconv.Itoa(int(c))
	}
}

func bandName(b registry.Band) string {
	switch b {
	case registry.BandBase:
		return "Base(裸传输)"
	case registry.BandCrypto:
		return "Crypto(TLS/REALITY)"
	case registry.BandCryptoObfs:
		return "CryptoObfs(伪装)"
	case registry.BandFrame:
		return "Frame(ws/grpc/h2…)"
	case registry.BandFlow:
		return "Flow(vision)"
	case registry.BandSession:
		return "Session(quic/mux)"
	case registry.BandProxy:
		return "Proxy(终端协议)"
	default:
		return "Band(" + strconv.Itoa(int(b)) + ")"
	}
}

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	interopPath := fs.String("interop", "", "互通结果 TSV(name<TAB>status<TAB>pass<TAB>fail)")
	out := fs.String("out", "report.html", "输出 HTML 路径")
	commit := fs.String("commit", os.Getenv("GITHUB_SHA"), "commit sha(默认取 $GITHUB_SHA)")
	_ = fs.Parse(args)

	// 1) 注册表自省 → 流式栈协议/传输清单(会话式出站不在注册表,靠 interop 表覆盖)。
	var protos, transports []pluginRow
	registry.Each(func(d registry.AnyDescriptor) {
		row := pluginRow{Name: d.Name(), Band: bandName(d.Band())}
		if caps := d.Provides(); len(caps) > 0 {
			ss := make([]string, 0, len(caps))
			for _, c := range caps {
				ss = append(ss, capName(c))
			}
			row.Provides = strings.Join(ss, ",")
		}
		if d.Band() == registry.BandProxy {
			row.Kind = "协议"
			protos = append(protos, row)
		} else {
			row.Kind = "传输/安全层"
			transports = append(transports, row)
		}
	})
	sort.Slice(protos, func(i, j int) bool { return protos[i].Name < protos[j].Name })
	sort.Slice(transports, func(i, j int) bool {
		return transports[i].Band+transports[i].Name < transports[j].Band+transports[j].Name
	})

	// 2) 读 CI 互通结果 TSV。
	var interop []interopRow
	var passN, totalN int
	if *interopPath != "" {
		if data, err := os.ReadFile(*interopPath); err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				f := strings.Split(line, "\t")
				if len(f) < 4 {
					continue
				}
				p, _ := strconv.Atoi(f[2])
				fa, _ := strconv.Atoi(f[3])
				interop = append(interop, interopRow{Name: f[0], Status: f[1], Pass: p, Fail: fa})
				totalN++
				if f[1] == "PASS" {
					passN++
				}
			}
		}
	}
	sort.Slice(interop, func(i, j int) bool { return interop[i].Name < interop[j].Name })

	data := struct {
		Commit             string
		Generated          string
		Protos, Transports []pluginRow
		Interop            []interopRow
		PassN, TotalN      int
	}{
		Commit:     shortSHA(*commit),
		Generated:  time.Now().UTC().Format("2006-01-02 15:04 MST"),
		Protos:     protos,
		Transports: transports,
		Interop:    interop,
		PassN:      passN,
		TotalN:     totalN,
	}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "report: create out:", err)
		os.Exit(1)
	}
	defer f.Close()
	if err := reportTmpl.Execute(f, data); err != nil {
		fmt.Fprintln(os.Stderr, "report: render:", err)
		os.Exit(1)
	}
	fmt.Printf("report: 写出 %s(%d 协议 + %d 传输,互通 %d/%d)\n", *out, len(protos), len(transports), passN, totalN)
}

func shortSHA(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	if s == "" {
		return "local"
	}
	return s
}

var reportTmpl = template.Must(template.New("report").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>NTR Report</title>
<style>
:root{--bg:#f7f8fa;--surface:#fff;--surface2:#f2f4f7;--ink:#1a2230;--muted:#5c6a7e;--line:#e2e6ec;--accent:#0e7490;--pass:#15803d;--fail:#b91c1c}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--surface:#161b22;--surface2:#1b222c;--ink:#e6edf3;--muted:#8b98a8;--line:#232b36;--accent:#22d3ee;--pass:#4ade80;--fail:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:"IBM Plex Sans",system-ui,"PingFang SC",sans-serif;line-height:1.55}
.wrap{max-width:1000px;margin:0 auto;padding:40px 20px 80px}
h1{font-size:28px;margin:0 0 6px}h2{font-size:19px;margin:36px 0 12px}
.sub{color:var(--muted);font-size:13px;font-family:ui-monospace,Menlo,monospace;margin:0 0 4px}
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--surface)}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{text-align:left;background:var(--surface2);padding:9px 12px;border-bottom:1px solid var(--line);font-size:12.5px}
td{padding:8px 12px;border-bottom:1px solid var(--line)}tr:last-child td{border-bottom:none}
.mono{font-family:ui-monospace,Menlo,monospace}
.pass{color:var(--pass);font-weight:600}.fail{color:var(--fail);font-weight:600}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;background:color-mix(in srgb,var(--accent) 15%,transparent);color:var(--accent)}
</style></head><body><div class="wrap">
<h1>NTR · 自研协议无关代理核心</h1>
<p class="sub">commit {{.Commit}} · 生成于 {{.Generated}} · 由 <span class="mono">ntr report</span> 在 GitHub Actions 中自省生成</p>
<p><span class="pill">互通 {{.PassN}}/{{.TotalN}} 脚本通过</span></p>

<h2>跨实现互通(CI 真跑 xray / mihomo / sing-box)</h2>
<div class="tw"><table><thead><tr><th>脚本</th><th>结果</th><th>PASS</th><th>FAIL</th></tr></thead><tbody>
{{range .Interop}}<tr><td class="mono">{{.Name}}</td><td class="{{if eq .Status "PASS"}}pass{{else}}fail{{end}}">{{.Status}}</td><td>{{.Pass}}</td><td>{{.Fail}}</td></tr>
{{else}}<tr><td colspan="4" style="color:var(--muted)">无互通结果(未传 --interop)</td></tr>{{end}}
</tbody></table></div>

<h2>已注册协议(注册表自省 · {{len .Protos}})</h2>
<div class="tw"><table><thead><tr><th>协议</th><th>Band</th><th>Provides</th></tr></thead><tbody>
{{range .Protos}}<tr><td class="mono">{{.Name}}</td><td>{{.Band}}</td><td class="mono">{{.Provides}}</td></tr>
{{end}}</tbody></table></div>

<h2>已注册传输 / 安全层(注册表自省 · {{len .Transports}})</h2>
<div class="tw"><table><thead><tr><th>传输</th><th>Band</th><th>Provides</th></tr></thead><tbody>
{{range .Transports}}<tr><td class="mono">{{.Name}}</td><td>{{.Band}}</td><td class="mono">{{.Provides}}</td></tr>
{{end}}</tbody></table></div>

<p class="sub" style="margin-top:40px">会话式出站(anytls/hy1/hy2/tuic/wireguard/ssh/masque/mieru/naive/shadowquic/trusttunnel)不走注册表,见互通表。</p>
</div></body></html>`))
