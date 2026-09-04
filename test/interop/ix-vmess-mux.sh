#!/bin/bash
# VMess mux(Xray mux.cool over vmess)交叉验证:xray vmess+mux 客户端 → NTR vmess 服务端。
# sing-vmess 的 HandleMuxConnection 把一条 vmess 承载拆成多条子流回调;NTR 经注入的 StreamDispatcher
# 把每条子流后台并发中继落地(不再拒绝第二条)→ 支持并发 mux。plain TCP(vmess 自包含 AEAD,免证书)。
#   验证:单请求 + N 并发请求(共享一条 mux 载体)全部通过。
set -u
NET=ix-vmm; PFX=ixvmm-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; UUID=11111111-2222-3333-4444-555555555555; CONC=20
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1
cat > $D/_vmm_srv.yaml <<Y
inbounds:
  - name: vm-in
    type: vmess
    listen: 0.0.0.0:10000
    uuid: "$UUID"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
cat > $D/_vmm_cli.json <<J
{"log":{"loglevel":"warning"},"inbounds":[{"port":1080,"listen":"0.0.0.0","protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"${PFX}s","port":10000,"users":[{"id":"$UUID","alterId":0,"security":"auto"}]}]},"streamSettings":{"security":"none"},"mux":{"enabled":true,"concurrency":8}}]}
J
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_vmm_srv.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
docker run -d --name ${PFX}c --network $NET -v $D/_vmm_cli.json:/c.json:ro ghcr.io/xtls/xray-core:latest -c /c.json >/dev/null 2>&1
sleep 3

echo "=== 单请求 ==="
s=FAIL; for i in 1 2 3 4 5; do
  docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null | grep -q Hostname && { s=PASS; break; }; sleep 1
done
echo "  [单请求 xray vmess+mux → NTR]  $s"

echo "=== $CONC 并发(共享一条 mux 载体)==="
res=$(docker run --rm --network $NET curlimages/curl:latest sh -c "
  for i in \$(seq 1 $CONC); do
    ( curl -s --max-time 12 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null | grep -q Hostname && echo OK || echo FAIL ) &
  done; wait
" 2>/dev/null | grep -c OK)
c=FAIL; [ "$res" = "$CONC" ] && c=PASS
echo "  [$CONC 并发 mux → NTR:$res/$CONC]  $c"
[ $c = FAIL ] && docker logs ${PFX}s 2>&1 | tail -4 | sed 's/^/    NTR-SRV:/'
cleanup; echo DONE