#!/bin/bash
# 回落伪装站(fallback)验证:NTR 入站配 fallback=真站后,协议握手失败(无 trojan/错口令/直连浏览器探测)时
# 不 RST/报错,而是把连接【原样中继到真站】—— 主动探测只看到一个正常网站(抗探测,对齐 xray/mihomo 的 fallback)。
# 禁改协议线格式:回落只是握手失败后的行为,发生在 TLS 之上(dest 收到解密后明文原始字节)。
# 验证点:① 直连 HTTPS 无 trojan → 回落到伪装站;② 有效 NTR 客户端(对口令)→ 真目标(回落不破正常流);
#         ③ 真 Xray trojan 客户端(对口令)→ NTR 服务端(带 fallback)→ 真目标(回落与跨实现互通共存);
#         ④ 行为对照:Xray trojan 服务端(带 fallback)直连探测 → 也回落到伪装站(证 NTR 行为与 Xray 一致);
#         ⑤⑥ 多站按 HTTP path、⑦⑧ 按 SNI 选伪装站;⑨⑩ xver(PROXY protocol 头把真实客户端 IP 透给伪装站)。
set -u
NET=ixfb; PFX=ixfb-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; PW="fbpass123"; SEQ=0
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
# srv:起 NTR 服务端。配置从 stdin 读、写入【独立目录】并挂目录(而非单文件)——根治 OrbStack 单文件
# bind-mount 在快速重写/挂载竞态下被截断→config 解析 fatal(承 orbstack-single-file-bindmount-truncation)。
# $1=附加 docker 参数(如 --network-alias);等 "监听于",容器若截断退出则重起最多 3 次。
srv(){ local extra="$1" cd="$D/cfg${SEQ}"; SEQ=$((SEQ+1)); mkdir -p "$cd"; cat > "$cd/c.yaml"
  local try; for try in 1 2 3; do
    docker rm -f ${PFX}s >/dev/null 2>&1
    docker run -d --name ${PFX}s --network $NET $extra -v $NTR:/ntr:ro -v $cd:/cfg:ro -v $D/fbcert.pem:/cert.pem:ro -v $D/fbkey.pem:/key.pem:ro alpine /ntr -config /cfg/c.yaml >/dev/null 2>&1
    wait_log ${PFX}s "监听于" 12 && return 0
  done; return 1; }
# probe:重负载下 curl 的 --retry 不覆盖 empty-reply(exit 52),伪装站中继偶发空回 → shell 级重跑取非空。
# 用法:probe <期望匹配正则> <curl 参数...> ;打印命中输出(或最后一次输出)。
probe(){ local want="$1"; shift; local r="" i; for i in 1 2 3 4 5 6; do
    r=$(docker run --rm --network $NET curlimages/curl:latest -sk --retry 3 --retry-connrefused --retry-delay 1 --max-time 15 "$@" 2>&1)
    echo "$r"|grep -qE "$want" && { echo "$r"; return; }; sleep 1
  done; echo "$r"; }
# 自签证书(带 SAN,Xray 客户端按 SAN 校验;NTR tls 层自签)
[ -f "$D/fbcert.pem" ] || docker run --rm -v $D:/w -w /w alpine sh -c 'apk add openssl>/dev/null 2>&1; openssl req -x509 -newkey rsa:2048 -keyout fbkey.pem -out fbcert.pem -days 3650 -nodes -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com" >/dev/null 2>&1; chmod 644 fbcert.pem fbkey.pem'
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami --name REAL-TARGET >/dev/null 2>&1
docker run -d --name ${PFX}decoy --network $NET traefik/whoami --name DECOY-SITE >/dev/null 2>&1
docker run -d --name ${PFX}db --network $NET traefik/whoami --name DECOY-BETA >/dev/null 2>&1
sleep 1

# NTR [tls, trojan] 服务端(自签)+ 单站 fallback
srv "" <<Y
inbounds:
  - name: fb-in
    type: trojan
    listen: 0.0.0.0:10000
    tls:
      cert-file: /cert.pem
      key-file: /key.pem
    users:
      - password: "$PW"
    outbound: direct
    fallback: "${PFX}decoy:80"
outbounds:
  - name: direct
    type: direct
Y

# ① 探测:直连 HTTPS 无 trojan → 伪装站
P=$(probe 'Name: DECOY-SITE' https://${PFX}s:10000/)
echo "  [① 直连HTTPS无trojan探测 → 伪装站]  $(echo "$P"|grep -q 'Name: DECOY-SITE' && echo PASS || echo FAIL)"

# ② 有效 NTR trojan 客户端 → 真目标
mkdir -p $D/cfgc; cat > $D/cfgc/c.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: trojan
    server: "${PFX}s:10000"
    secret: "$PW"
    tls:
      sni: example.com
      insecure: true
Y
docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/cfgc:/cfg:ro alpine /ntr -config /cfg/c.yaml >/dev/null 2>&1
wait_log ${PFX}c "监听于" 15
V=$(probe 'Name: REAL-TARGET' -x socks5h://${PFX}c:1080 http://${PFX}target/)
echo "  [② 有效 NTR trojan 客户端 → 真目标(回落不破正常流)]  $(echo "$V"|grep -q 'Name: REAL-TARGET' && echo PASS || echo FAIL)"
docker rm -f ${PFX}c >/dev/null 2>&1

# ③ 真 Xray trojan 客户端 → NTR 服务端(带 fallback)→ 真目标
mkdir -p $D/cfgxc; cat > $D/cfgxc/c.json <<Y
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"${PFX}s","port":10000,"password":"$PW"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"usage":"verify","certificateFile":"/ca.pem"}]}}}]}
Y
docker run -d --name ${PFX}xc --network $NET -v $D/cfgxc:/cfg:ro -v $D/fbcert.pem:/ca.pem:ro ghcr.io/xtls/xray-core:latest run -c /cfg/c.json >/dev/null 2>&1
sleep 3
VX=$(probe 'Name: REAL-TARGET' -x socks5h://${PFX}xc:1080 http://${PFX}target/)
echo "  [③ 真 Xray trojan 客户端 → NTR(带fallback)服务端 → 真目标]  $(echo "$VX"|grep -q 'Name: REAL-TARGET' && echo PASS || echo FAIL)"
docker rm -f ${PFX}xc ${PFX}s >/dev/null 2>&1

# ④ 行为对照:真 Xray trojan 服务端(带 fallback)→ 直连探测 → 也回落到伪装站
mkdir -p $D/cfgxs; cat > $D/cfgxs/c.json <<Y
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"trojan","settings":{"clients":[{"password":"$PW"}],"fallbacks":[{"dest":"${PFX}decoy:80"}]},"streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/cert.pem","keyFile":"/key.pem"}]}}}],"outbounds":[{"protocol":"freedom"}]}
Y
docker run -d --name ${PFX}xs --network $NET -v $D/cfgxs:/cfg:ro -v $D/fbcert.pem:/cert.pem:ro -v $D/fbkey.pem:/key.pem:ro ghcr.io/xtls/xray-core:latest run -c /cfg/c.json >/dev/null 2>&1
sleep 3
PX=$(probe 'Name: DECOY-SITE' https://${PFX}xs:10000/)
echo "  [④ 对照:Xray trojan 服务端(带fallback)直连探测 → 伪装站]  $(echo "$PX"|grep -q 'Name: DECOY-SITE' && echo 'PASS(NTR 行为与 Xray 一致)' || echo FAIL)"
docker rm -f ${PFX}xs >/dev/null 2>&1

# ⑤⑥ 多站回落(NTR fallbacks 列表):按 HTTP path 前缀路由到不同伪装站(对齐 xray fallbacks 的 path 维)
srv "" <<Y
inbounds:
  - name: fb-in
    type: trojan
    listen: 0.0.0.0:10000
    tls:
      cert-file: /cert.pem
      key-file: /key.pem
    users:
      - password: "$PW"
    outbound: direct
    fallbacks:
      - path: "/alpha"
        dest: "${PFX}decoy:80"
      - dest: "${PFX}db:80"
outbounds:
  - name: direct
    type: direct
Y
PA=$(probe 'Name: DECOY' https://${PFX}s:10000/alpha)
echo "  [⑤ 多站回落 GET /alpha → 规则1 伪装站A(DECOY-SITE)]  $(echo "$PA"|grep -q 'Name: DECOY-SITE' && echo PASS || echo FAIL)"
PB=$(probe 'Name: DECOY' https://${PFX}s:10000/beta)
echo "  [⑥ 多站回落 GET /beta → 默认规则2 伪装站B(DECOY-BETA)]  $(echo "$PB"|grep -q 'Name: DECOY-BETA' && echo PASS || echo FAIL)"

# ⑦⑧ SNI 维回落(对齐 xray name 维):按 ClientHello ServerName 路由到不同伪装站
# 用 Docker 网络别名让 alpha.test/beta.test 都解析到 NTR 服务端(curl 以此为 SNI,免 --resolve+取 IP 的竞态)
srv "--network-alias alpha.test --network-alias beta.test" <<Y
inbounds:
  - name: fb-in
    type: trojan
    listen: 0.0.0.0:10000
    tls:
      cert-file: /cert.pem
      key-file: /key.pem
    users:
      - password: "$PW"
    outbound: direct
    fallbacks:
      - sni:
          - "alpha.test"
        dest: "${PFX}decoy:80"
      - dest: "${PFX}db:80"
outbounds:
  - name: direct
    type: direct
Y
SA=$(probe 'Name: DECOY' https://alpha.test:10000/)
echo "  [⑦ SNI=alpha.test → 规则1 伪装站A(DECOY-SITE)]  $(echo "$SA"|grep -q 'Name: DECOY-SITE' && echo PASS || echo FAIL)"
SB=$(probe 'Name: DECOY' https://beta.test:10000/)
echo "  [⑧ SNI=beta.test → 默认规则2 伪装站B(DECOY-BETA)]  $(echo "$SB"|grep -q 'Name: DECOY-BETA' && echo PASS || echo FAIL)"

# ⑨⑩ xver 维(对齐 xray fallbacks 的 xver:PROXY protocol 头把真实客户端 IP 透给伪装站)
# 伪装站换成读 PROXY 头的小程序:v1 收 "PROXY TCP4 <src> ..." / v2 收二进制签名头 → 回 "PROXY-OK src=<src>",否则 "NO-PROXY"。
mkdir -p $D/xverdecoy
cat > $D/xverdecoy/main.go <<'GO'
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
)

var v2sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

func main() {
	ln, _ := net.Listen("tcp", "0.0.0.0:9000")
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			body := "NO-PROXY"
			// PROXY protocol v2(二进制):12B 签名 + verCmd + fam + 2B 地址区长 + 地址区(IPv4:src[4] dst[4] sport dport)。
			// 先 Peek(16) 完整头再取地址区长(避免 Discard 与短读竞态);否则退回 v1 文本行解析。
			if h, _ := br.Peek(16); len(h) == 16 && bytes.Equal(h[:12], v2sig) {
				br.Discard(16)
				alen := int(h[14])<<8 | int(h[15])
				ab := make([]byte, alen)
				if _, err := readFull(br, ab); err == nil && (h[13]&0xF0) == 0x10 && len(ab) >= 4 {
					body = "PROXY-OK src=" + net.IP(ab[:4]).String()
				}
			} else {
				line, _ := br.ReadString('\n')
				line = strings.TrimRight(line, "\r\n")
				body = "NO-PROXY first=" + line
				if f := strings.Fields(line); len(f) >= 6 && f[0] == "PROXY" {
					body = "PROXY-OK src=" + f[2]
				}
			}
			fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		}(c)
	}
}

func readFull(r *bufio.Reader, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		m, err := r.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
GO
printf 'module xverdecoy\ngo 1.21\n' > $D/xverdecoy/go.mod
docker run --rm -v $D/xverdecoy:/src -w /src -e CGO_ENABLED=0 golang:alpine go build -o xverdecoy-bin . >/dev/null 2>&1
docker run -d --name ${PFX}xd --network $NET -v $D/xverdecoy/xverdecoy-bin:/d:ro alpine /d >/dev/null 2>&1; sleep 1
for xv in 0 1 2; do
  XVER=""; [ "$xv" != 0 ] && XVER="        xver: $xv"
  srv "" <<Y
inbounds:
  - name: fb-in
    type: trojan
    listen: 0.0.0.0:10000
    tls:
      cert-file: /cert.pem
      key-file: /key.pem
    users:
      - password: "$PW"
    outbound: direct
    fallbacks:
      - dest: "${PFX}xd:9000"
$XVER
outbounds:
  - name: direct
    type: direct
Y
  RX=$(probe 'PROXY' https://${PFX}s:10000/ | tail -1)
  if [ "$xv" = 0 ]; then
    echo "  [⑨ 未开 xver → 伪装站收到裸 HTTP(无 PROXY 头)]  $(echo "$RX"|grep -q 'NO-PROXY' && echo PASS || echo "FAIL($RX)")"
  else
    echo "  [⑩ xver=$xv → 伪装站收到 PROXY 头带真实客户端 IP]  $(echo "$RX"|grep -q 'PROXY-OK src=' && echo "PASS($RX)" || echo "FAIL($RX)")"
  fi
done
cleanup; echo DONE
