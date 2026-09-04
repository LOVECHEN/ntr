#!/bin/bash
# tlsmirror(隐写进真 TLS 会话的镜像/诱骗路由传输;v2fly v2ray-core v5 起源,mihomo 移植;主线 Xray/XTLS
# 与 sing-box 均无)交叉验证:NTR ⇄ mihomo(vmess over tlsmirror)。三方共用一台【真 TLS1.3 诱骗后端】。
#
# 线格式逐字节承 mihomo/v2ray transport/tlsmirror(见 transport/tlsmirror/*.go 头注),零协议改动:
#   隐蔽记录 = app-data 记录,fragment=AES128-GCM(HKDF 派生密钥, 隐式 8B 小端计数 nonce, 明文);识别靠
#   试解密;密钥 = HKDF-SHA256(primaryKey||clientRandom||serverRandom, "...:tlsmirror-encryption:{c2s|s2c}")。
# 覆盖:default(A/B/C)+ 可选抗检测层 transport-layer-padding、sequence-watermarking(各 A/B,对 mihomo
# 对应 interop 用例)。★配置:primary-key 两端共享(base64 32B);载体 SNI=真后端域名;服务端透明中继不
# 终结 TLS→不需证书,dest 指真后端。v1 仅 TLS1.3 载体,不含 enrollment/流量生成器/uTLS 指纹(可选层,不改线格式)。
#
# 就绪同步(消除散点 flake 的真修复):各容器起后【轮询监听日志】就绪,不用盲 sleep;★未就绪即删了重挂
# (run_*_ready,至多 3 次)—— 散点失败真因是【OrbStack 单文件 bind-mount 高负载下偶给容器截断视图】→
# 配置解析 fatal → 容器退出(实测 "yaml: line 2: did not find expected ',' or '}'",与 mekya DoH 同类),
# 重挂时文件已同步再读即好。载体多跳握手另有 pullr 6 次兜底。线格式确定性权威仍是进程内
# `go test -race ./transport/tlsmirror/`(6 组 default/padding/watermark/pw/tls12/tls12+pw 全过,无 Docker 无 flake)。
set -u
NET=ix-tm; PFX=ixtm-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; UUID="11111111-1111-1111-1111-111111111111"
KEY=$(docker run --rm alpine sh -c 'apk add openssl >/dev/null 2>&1; openssl rand -base64 32')
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
# 诱骗后端(真 TLS1.3 服务器):源在 tlsmirror-decoy/,缺二进制则用 Docker 静态编出(不污染本机)。
SD="$(cd "$(dirname "$0")" && pwd)/tlsmirror-decoy"
if [ ! -x "$D/decoy/decoy-bin" ]; then
  mkdir -p "$D/decoy"; cp "$SD/main.go" "$SD/go.mod" "$D/decoy/"
  docker run --rm -v "$D/decoy":/src -w /src -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 golang:alpine go build -o decoy-bin . >/dev/null 2>&1
fi
[ -x "$D/decoy/decoy-bin" ] || { echo "诱骗后端编译失败"; exit 1; }
# setup [decoy_env]:decoy_env 非空(如 DECOY_TLS12=1)→ 诱骗后端只走 TLS1.2 AES-GCM(供显式 nonce 用例)
setup(){ cleanup; docker network create $NET >/dev/null 2>&1; docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1; docker run -d --name ${PFX}decoy --network $NET ${1:+-e} ${1:-} -v $D/decoy/decoy-bin:/decoy:ro alpine /decoy >/dev/null 2>&1; sleep 1; }
# TLS1.2 显式 nonce 推荐识别套件(与 mihomo RecommendedExplicitNonceCipherSuites 一致)
SUITES='[156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,49195,49196,49197,49198,49199,49200,49201,49202,49290,49291,49293,49316,49317,49318,49319,49320,49321,49322,49323,49324,49325,49326,49327,52392,52393,52394,52395,52396,52397,52398]'
run_ntr(){ docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_mi(){ docker run -d --name $1 --network $NET -v $2:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }
pull(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://$1:1080 http://${PFX}target/ 2>&1; }
# wait_log $容器 $就绪标记 [$最长秒=20]:轮询容器日志到出现监听就绪标记再返回(替代盲 sleep,消除冷启动竞态)。
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1 | grep -q "$2" && return 0; sleep 0.5; done; return 1; }
# run_*_ready:起容器 + 轮询就绪;★未就绪就删了重挂(至多 3 次)。真因是【OrbStack 单文件 bind-mount 在高
# 容器 I/O 负载下偶给容器一份截断视图】→ 配置解析 fatal → 容器退出 → 就绪标记不出现(实测报
# "yaml: line 2: did not find expected ',' or '}'",与 mekya DoH 那次同类)。重挂时文件已落盘同步,再读即好。
run_ntr_ready(){ local i; for i in 1 2 3; do docker rm -f "$1" >/dev/null 2>&1; run_ntr "$1" "$2"; wait_log "$1" "监听于" 15 && return 0; done; return 1; }
run_mi_ready(){ local i; for i in 1 2 3; do docker rm -f "$1" >/dev/null 2>&1; run_mi "$1" "$2"; wait_log "$1" "listening at" 15 && return 0; done; return 1; }
# 载体多跳握手仍偶发首连未热,重试 6 次兜底(对齐 mihomo 自测 RoundTripWithRetry)。
pullr(){ local o i; for i in 1 2 3 4 5 6; do o=$(pull "$1"); echo "$o"|grep -q Hostname && { echo "$o"; return; }; sleep 2; done; echo "$o"; }
chk(){ echo "$1" | grep -q Hostname && echo PASS || echo FAIL; }

# 参数化特性:$1=标签 $2=NTR tlsmirror 块附加行(块式,6 空格缩进,空=无) $3=mihomo 客户端 tlsmirror-opts 附加 $4=mihomo 服务端 tlsmirror-config 附加 $5=是否含自环 $6=诱骗后端 env(如 DECOY_TLS12=1)
feat(){
  local name="$1" ntrkv="$2" miopt="$3" misrv="$4" selfloop="${5:-}" decoyenv="${6:-}"
  # A: mihomo vmess+tlsmirror 客户端 → NTR 服务端
  setup "$decoyenv"
  cat > $D/_s.yaml <<Y
inbounds:
  - name: vm-in
    type: vmess
    listen: 0.0.0.0:10000
    tlsmirror:
      dest: "${PFX}decoy:443"
      primary-key: "$KEY"
$ntrkv
    uuid: "$UUID"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
  run_ntr_ready ${PFX}s $D/_s.yaml
  cat > $D/_c.yaml <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - {name: p, type: vmess, server: ${PFX}s, port: 10000, uuid: $UUID, alterId: 0, cipher: auto, tls: true, servername: decoy.example.com, skip-cert-verify: true, tlsmirror-opts: {primary-key: "$KEY"$miopt}}
rules: ["MATCH,p"]
Y
  run_mi_ready ${PFX}c $D/_c.yaml
  echo "  [$name A. mihomo 客户端 → NTR 服务端]  $(chk "$(pullr ${PFX}c)")"
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
  # B: NTR 客户端 → mihomo vmess+tlsmirror 服务端
  cat > $D/_s.yaml <<Y
log-level: warning
listeners:
  - {name: vm-in, type: vmess, listen: 0.0.0.0, port: 10000, users: [{username: u, uuid: $UUID, alterId: 0}], tlsmirror-config: {primary-key: "$KEY", dest: "${PFX}decoy:443"$misrv}}
Y
  run_mi_ready ${PFX}s $D/_s.yaml
  cat > $D/_c.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: vmess
    server: "${PFX}s:10000"
    uuid: "$UUID"
    tlsmirror:
      sni: decoy.example.com
      insecure: true
      primary-key: "$KEY"
$ntrkv
Y
  run_ntr_ready ${PFX}c $D/_c.yaml
  echo "  [$name B. NTR 客户端 → mihomo 服务端]  $(chk "$(pullr ${PFX}c)")"
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
  if [ -n "$selfloop" ]; then
    cat > $D/_s.yaml <<Y
inbounds:
  - name: vm-in
    type: vmess
    listen: 0.0.0.0:10000
    tlsmirror:
      dest: "${PFX}decoy:443"
      primary-key: "$KEY"
$ntrkv
    uuid: "$UUID"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
    run_ntr_ready ${PFX}s $D/_s.yaml
    cat > $D/_c.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: vmess
    server: "${PFX}s:10000"
    uuid: "$UUID"
    tlsmirror:
      sni: decoy.example.com
      insecure: true
      primary-key: "$KEY"
$ntrkv
Y
    run_ntr_ready ${PFX}c $D/_c.yaml
    echo "  [$name C. NTR↔NTR 自环]  $(chk "$(pullr ${PFX}c)")"
  fi
}

feat "default"   ""              ""                                      ""                                      yes
feat "tls12-explicit-nonce" "      explicit-nonce: true" ", explicit-nonce-ciphersuites: $SUITES" ", explicit-nonce-ciphersuites: $SUITES" "" "DECOY_TLS12=1"
feat "padding"   "      padding: true"   ", transport-layer-padding: {enabled: true}"   ", transport-layer-padding: {enabled: true}"
feat "watermark" "      watermark: true" ", sequence-watermarking-enabled: true"        ", sequence-watermarking-enabled: true"
cleanup; echo DONE
