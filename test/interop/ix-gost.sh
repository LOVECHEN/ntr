#!/bin/bash
# gost relay(go-gost/relay v1 协议;mihomo 作 type: gost-relay 出站暴露,但无 gost 服务端;Xray/sing-box 无)
# 交叉验证:A mihomo gost-relay 客户端 → NTR gost 服务端;B NTR gost 客户端 → 真 go-gost v3 relay 服务端
# (gogost/gost 官方镜像,权威对端);C NTR↔NTR 自环。线格式逐字节承 go-gost/relay(mihomo transport/gost 亦
# copy 自它),零协议改动。gost relay 自身无加密,可裸跑(本测)或叠 [tls, gost]。
# ★go-gost v3 relay 响应【懒发】:connect 后不立回,把 [0x01][status][2B] 前缀拼在目标首段下行前 → NTR 客户端
#   惰性剥响应(见 proto/gost 头注),否则与"服务端等客户端先发数据"死锁。
# 就绪同步 + 未就绪重挂:见 ix-tlsmirror.sh 头注。
set -u
NET=ixg; PFX=ixg-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
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
NTR_SRV='inbounds: [{listen: 0.0.0.0:10000, layers: [{type: gost}], outbound: direct}]
outbounds: [{name: direct, type: direct}]'
NTR_CLI='inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds: [{name: up, type: proxy, server: "SRV:10000", layers: [{type: gost}]}]'

# A: mihomo gost-relay 客户端 → NTR gost 服务端
setup
printf '%s\n' "$NTR_SRV" > $D/_s.yaml
run_ntr_ready ${PFX}s $D/_s.yaml
cat > $D/_c.yaml <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies: [{name: p, type: gost-relay, server: ${PFX}s, port: 10000}]
rules: ["MATCH,p"]
Y
run_mi_ready ${PFX}c $D/_c.yaml
echo "  [A. mihomo gost-relay 客户端 → NTR gost 服务端]  $(chk "$(pullr ${PFX}c)")"
docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1

# B: NTR gost 客户端 → 真 go-gost v3 relay 服务端(权威对端)
docker run -d --name ${PFX}gost --network $NET gogost/gost:latest -L "relay://:10000" >/dev/null 2>&1
wait_log ${PFX}gost "listening on" 15
printf '%s\n' "${NTR_CLI/SRV/${PFX}gost}" > $D/_c.yaml
run_ntr_ready ${PFX}c $D/_c.yaml
echo "  [B. NTR gost 客户端 → 真 go-gost v3 服务端]  $(chk "$(pullr ${PFX}c)")"
docker rm -f ${PFX}gost ${PFX}c >/dev/null 2>&1

# C: NTR↔NTR 自环
printf '%s\n' "$NTR_SRV" > $D/_s.yaml
run_ntr_ready ${PFX}s $D/_s.yaml
printf '%s\n' "${NTR_CLI/SRV/${PFX}s}" > $D/_c.yaml
run_ntr_ready ${PFX}c $D/_c.yaml
echo "  [C. NTR↔NTR 自环]  $(chk "$(pullr ${PFX}c)")"
cleanup; echo DONE
