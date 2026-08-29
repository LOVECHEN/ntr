#!/bin/bash
# kcptun(xtaci/kcptun 的 KCP+RS-FEC+可选 block 加密+可选 snappy+smux 隧道;mihomo 作 shadowsocks 的
# plugin: kcptun 暴露,client+server 两端俱全;xray/sing-box 无)交叉验证:NTR ⇄ mihomo(SS over kcptun)。
# 线格式逐字节承 mihomo transport/kcptun(其 copy 自 xtaci/kcptun),复用同版本 metacubex/kcp-go、
# metacubex/smux、golang/snappy → 直接互通。NTR 叠法 [kcptun, shadowsocks]。
# ★两端须一致:key/crypt/mode(nodelay/interval/resend/nc)/datashard/parityshard/mtu/窗口/smuxver/nocomp,
#   以及 SS 的 method/password。kcptun 走 UDP。
# 就绪同步 + 未就绪重挂:见 ix-tlsmirror.sh 头注(OrbStack 单文件 bind-mount 高负载截断)。
set -u
NET=ixkt; PFX=ixkt-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
KKEY="mykcpkey123"; SSM="aes-256-gcm"; SSP="sspass"; UUID_UNUSED=""
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
run_ntr(){ docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_mi(){ docker run -d --name $1 --network $NET -v $2:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1 | grep -q "$2" && return 0; sleep 0.5; done; return 1; }
run_ntr_ready(){ local i; for i in 1 2 3; do docker rm -f "$1" >/dev/null 2>&1; run_ntr "$1" "$2"; wait_log "$1" "监听于" 15 && return 0; done; return 1; }
run_mi_ready(){ local i; for i in 1 2 3; do docker rm -f "$1" >/dev/null 2>&1; run_mi "$1" "$2"; wait_log "$1" "listening at" 15 && return 0; done; return 1; }
pull(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://$1:1080 http://${PFX}target/ 2>&1; }
pullr(){ local o i; for i in 1 2 3 4 5 6; do o=$(pull "$1"); echo "$o"|grep -q Hostname && { echo "$o"; return; }; sleep 2; done; echo "$o"; }
chk(){ echo "$1" | grep -q Hostname && echo PASS || echo FAIL; }
setup(){ cleanup; docker network create $NET >/dev/null 2>&1; docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1; sleep 1; }

setup
# A: mihomo ss+kcptun 客户端 → NTR [kcptun, shadowsocks] 服务端
cat > $D/_s.yaml <<Y
inbounds: [{listen: 0.0.0.0:10000, layers: [{type: kcptun, key: "$KKEY", crypt: aes, mode: fast}, {type: shadowsocks, method: $SSM, password: "$SSP"}], outbound: direct}]
outbounds: [{name: direct, type: direct}]
Y
run_ntr_ready ${PFX}s $D/_s.yaml
cat > $D/_c.yaml <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - name: p
    type: ss
    server: ${PFX}s
    port: 10000
    cipher: $SSM
    password: "$SSP"
    plugin: kcptun
    plugin-opts:
      key: "$KKEY"
      crypt: aes
      mode: fast
rules: ["MATCH,p"]
Y
run_mi_ready ${PFX}c $D/_c.yaml
echo "  [A. mihomo ss+kcptun 客户端 → NTR 服务端]  $(chk "$(pullr ${PFX}c)")"
docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1

# B: NTR [kcptun, shadowsocks] 客户端 → mihomo ss+kcptun 服务端
cat > $D/_s.yaml <<Y
log-level: warning
listeners:
  - name: ss-in
    type: shadowsocks
    listen: 0.0.0.0
    port: 10000
    password: "$SSP"
    cipher: $SSM
    kcp-tun:
      enable: true
      key: "$KKEY"
      crypt: aes
      mode: fast
Y
run_mi_ready ${PFX}s $D/_s.yaml
cat > $D/_c.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", layers: [{type: kcptun, key: "$KKEY", crypt: aes, mode: fast}, {type: shadowsocks, method: $SSM, password: "$SSP"}]}
Y
run_ntr_ready ${PFX}c $D/_c.yaml
echo "  [B. NTR 客户端 → mihomo ss+kcptun 服务端]  $(chk "$(pullr ${PFX}c)")"
docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1

# C: NTR↔NTR 自环
cat > $D/_s.yaml <<Y
inbounds: [{listen: 0.0.0.0:10000, layers: [{type: kcptun, key: "$KKEY", crypt: aes, mode: fast}, {type: shadowsocks, method: $SSM, password: "$SSP"}], outbound: direct}]
outbounds: [{name: direct, type: direct}]
Y
run_ntr_ready ${PFX}s $D/_s.yaml
cat > $D/_c.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", layers: [{type: kcptun, key: "$KKEY", crypt: aes, mode: fast}, {type: shadowsocks, method: $SSM, password: "$SSP"}]}
Y
run_ntr_ready ${PFX}c $D/_c.yaml
echo "  [C. NTR↔NTR 自环]  $(chk "$(pullr ${PFX}c)")"
cleanup; echo DONE
