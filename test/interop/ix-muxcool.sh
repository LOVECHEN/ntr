#!/bin/bash
# Mux.cool(Xray mux)交叉验证:承载连接拨魔术目标 v1.mux.cool:9527,其上多子流复用。
#   A. xray vless+mux 客户端 → NTR vless 服务端(NTR 解复用 handleMuxCoolCarrier → direct → whoami)
#   B. NTR vless+mux.cool 客户端 → xray vless 服务端(xray 自动解 mux.cool → freedom → whoami)
# 载体协议无关(此处 vless);对 mux.cool 线格式零改动(复用项目自研 muxcool 编解码)。
set -u
NET=ix-muxc; PFX=ixmc-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
UUID=11111111-2222-3333-4444-555555555555
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

xray(){ docker run -d --name $1 --network $NET -v $2:/c.json:ro ghcr.io/xtls/xray-core:latest -c /c.json >/dev/null 2>&1; }
ntr(){  docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
pull(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://$1:1080 http://${PFX}target/ 2>/dev/null; }

# ---- A. NTR 服务端 <- xray mux 客户端 ----
cat > $D/_mc_ntrsrv.yaml <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: vless}]
    users: [{uuid: "$UUID"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
cat > $D/_mc_xraycli.json <<J
{"log":{"loglevel":"warning"},
 "inbounds":[{"port":1080,"listen":"0.0.0.0","protocol":"socks","settings":{"udp":true}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"${PFX}s","port":10000,"users":[{"id":"$UUID","encryption":"none"}]}]},"streamSettings":{"network":"tcp"},"mux":{"enabled":true,"concurrency":8}}]}
J
ntr  ${PFX}s $D/_mc_ntrsrv.yaml;  sleep 2
xray ${PFX}c $D/_mc_xraycli.json; sleep 2
okA=FAIL; for i in 1 2 3 4 5; do echo "$(pull ${PFX}c)" | grep -q Hostname && { okA=PASS; break; }; sleep 1; done
echo "  [A. NTR 服务端 <- xray mux 客户端]  $okA"
[ $okA = FAIL ] && { docker logs ${PFX}s 2>&1|tail -3|sed 's/^/    NTR-SRV:/'; docker logs ${PFX}c 2>&1|grep -iE 'mux|fail'|tail -3|sed 's/^/    XRAY-CLI:/'; }
docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1

# ---- B. NTR mux.cool 客户端 -> xray 服务端 ----
cat > $D/_mc_xraysrv.json <<J
{"log":{"loglevel":"warning"},
 "inbounds":[{"port":10000,"listen":"0.0.0.0","protocol":"vless","settings":{"clients":[{"id":"$UUID"}],"decryption":"none"}}],
 "outbounds":[{"protocol":"freedom"}]}
J
cat > $D/_mc_ntrcli.yaml <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", secret: "$UUID", layers: [{type: vless}], mux: {protocol: cool}}
Y
xray ${PFX}s $D/_mc_xraysrv.json; sleep 2
ntr  ${PFX}c $D/_mc_ntrcli.yaml;  sleep 2
okB=FAIL; for i in 1 2 3 4 5; do echo "$(pull ${PFX}c)" | grep -q Hostname && { okB=PASS; break; }; sleep 1; done
echo "  [B. NTR mux.cool 客户端 -> xray 服务端]  $okB"
[ $okB = FAIL ] && { docker logs ${PFX}c 2>&1|tail -4|sed 's/^/    NTR-CLI:/'; docker logs ${PFX}s 2>&1|grep -iE 'mux|fail|accept'|tail -3|sed 's/^/    XRAY-SRV:/'; }
docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1

# ---- C. NTR mux.cool 客户端 -> NTR 服务端(自环:自研客户端+服务端对拨)----
ntr ${PFX}s $D/_mc_ntrsrv.yaml; sleep 2
ntr ${PFX}c $D/_mc_ntrcli.yaml; sleep 2
okC=FAIL; for i in 1 2 3 4 5; do echo "$(pull ${PFX}c)" | grep -q Hostname && { okC=PASS; break; }; sleep 1; done
echo "  [C. NTR mux.cool 客户端 -> NTR 服务端(自环)]  $okC"
[ $okC = FAIL ] && { docker logs ${PFX}c 2>&1|tail -3|sed 's/^/    NTR-CLI:/'; docker logs ${PFX}s 2>&1|tail -3|sed 's/^/    NTR-SRV:/'; }
cleanup; echo DONE