#!/bin/bash
# Mux.cool over Shadowsocks 交叉验证:证明 mux.cool 与承载协议正交(协议无关)。
# ss 无 Mux 命令 → 载体在线上直接带地址 v1.mux.cool:9527(地址式),NTR 服务端 isMuxCoolCarrier 直接
# 识别、客户端 outbound/muxcool 包任意 base(此处 ss)—— 均零额外代码(与 vless 的命令式载体互补)。
#   A. xray ss+mux 客户端 → NTR ss 服务端
#   B. NTR ss+mux.cool 客户端 → xray ss 服务端
set -u
NET=ix-mcs; PFX=ixmcs-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; PW=ssmuxpass12345; M=aes-256-gcm
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1
xray(){ docker run -d --name $1 --network $NET -v $2:/c.json:ro ghcr.io/xtls/xray-core:latest -c /c.json >/dev/null 2>&1; }
ntr(){  docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
pull(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://$1:1080 http://${PFX}target/ 2>/dev/null; }

# A. NTR ss 服务端 <- xray ss+mux 客户端
cat > $D/_mcs_ntrsrv.yaml <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: shadowsocks, method: $M, password: "$PW"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
cat > $D/_mcs_xraycli.json <<J
{"log":{"loglevel":"warning"},"inbounds":[{"port":1080,"listen":"0.0.0.0","protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{"address":"${PFX}s","port":10000,"method":"$M","password":"$PW"}]},"mux":{"enabled":true,"concurrency":8}}]}
J
ntr ${PFX}s $D/_mcs_ntrsrv.yaml; sleep 2
xray ${PFX}c $D/_mcs_xraycli.json; sleep 2
okA=FAIL; for i in 1 2 3 4 5; do echo "$(pull ${PFX}c)" | grep -q Hostname && { okA=PASS; break; }; sleep 1; done
echo "  [A. NTR ss 服务端 <- xray ss+mux 客户端]  $okA"
[ $okA = FAIL ] && { docker logs ${PFX}s 2>&1|tail -3|sed 's/^/    NTR-SRV:/'; docker logs ${PFX}c 2>&1|grep -iE 'mux|fail'|tail -3|sed 's/^/    XRAY-CLI:/'; }
docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1

# B. NTR ss+mux.cool 客户端 -> xray ss 服务端
cat > $D/_mcs_xraysrv.json <<J
{"log":{"loglevel":"warning"},"inbounds":[{"port":10000,"listen":"0.0.0.0","protocol":"shadowsocks","settings":{"method":"$M","password":"$PW","network":"tcp"}}],"outbounds":[{"protocol":"freedom"}]}
J
cat > $D/_mcs_ntrcli.yaml <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", layers: [{type: shadowsocks, method: $M, password: "$PW"}], mux: {protocol: cool}}
Y
xray ${PFX}s $D/_mcs_xraysrv.json; sleep 2
ntr  ${PFX}c $D/_mcs_ntrcli.yaml;  sleep 2
okB=FAIL; for i in 1 2 3 4 5; do echo "$(pull ${PFX}c)" | grep -q Hostname && { okB=PASS; break; }; sleep 1; done
echo "  [B. NTR ss+mux.cool 客户端 -> xray ss 服务端]  $okB"
[ $okB = FAIL ] && { docker logs ${PFX}c 2>&1|tail -4|sed 's/^/    NTR-CLI:/'; docker logs ${PFX}s 2>&1|grep -iE 'mux|fail'|tail -3|sed 's/^/    XRAY-SRV:/'; }
cleanup; echo DONE