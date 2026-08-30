#!/bin/bash
# 每用户限额验证(承设计 §6.2-6.3):max-conns(接入 CAS 拒新)+ rate(稀疏泄流点令牌桶限速)。
#   A. max-conns=2:2 条慢下载占满 → 第 3 条接入被拒;/stats 见 conns_live=2 + rejected≥1。
#   B. rate=16mbps:下载 20MiB,实测吞吐 ≈ 2MiB/s(16mbps)。
set -u
NET=ix-lim; PFX=ixlim-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; UUID=11111111-2222-3333-4444-555555555555
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}big --network $NET python:3-alpine sh -c "python3 -c \"open('/f','wb').write(b'x'*20971520)\"; cd /; python3 -m http.server 80" >/dev/null 2>&1
docker run -d --name ${PFX}who --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

start_srv(){ # $1 = users-line
  docker rm -f ${PFX}s >/dev/null 2>&1
  cat > $D/_lim_srv.yaml <<Y
metrics: {listen: 0.0.0.0:9091, access: ["0.0.0.0/0"]}
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: vless}]
    users: [{uuid: "$UUID", $1}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
  docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_lim_srv.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
}
cat > $D/_lim_cli.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", secret: "$UUID", layers: [{type: vless}]}
Y
start_cli(){ docker rm -f ${PFX}c >/dev/null 2>&1; docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_lim_cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
S(){ docker inspect ${PFX}s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null; }

echo "=== A. max-conns=2 ==="
start_srv "max-conns: 2"; start_cli; sleep 6
# 起 4 条慢下载(远超 max-conns=2)—— 超额的必被拒。判据看累计 rejected≥1 + 活跃≤2,
# 不依赖"恰好2条同时 live"这种脆弱时序(旧写法在 CI/本地都偶发 conns_live=1 假失败)。
docker run -d --name ${PFX}dl --network $NET curlimages/curl:latest sh -c "for i in 1 2 3 4 5 6; do curl -s --max-time 40 --limit-rate 60k -x socks5h://${PFX}c:1080 http://${PFX}big/f -o /dev/null & done; wait" >/dev/null 2>&1
# 轮询到出现拒绝(max-conns 生效的确定信号)或超时
rej=0; live=0
for _ in $(seq 1 30); do
  stats=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 4 http://$(S):9091/stats 2>/dev/null)
  rej=$(echo "$stats" | grep -oE '"rejected":[0-9]+' | head -1 | grep -oE '[0-9]+')
  live=$(echo "$stats" | grep -oE '"conns_live":[0-9]+' | head -1 | grep -oE '[0-9]+')
  [ "${rej:-0}" -ge 1 ] && break
  sleep 1
done
a=FAIL; [ "${rej:-0}" -ge 1 ] && [ "${live:-0}" -le 2 ] && a=PASS
echo "  4条并发/上限2 → 被拒=${rej:-0}  活跃=${live:-0}(≤2)   [max-conns 拒超额]  $a"
docker rm -f ${PFX}dl >/dev/null 2>&1

echo "=== B. rate=16mbps(≈2MiB/s),下载 20MiB ==="
start_srv 'rate: 16mbps'; start_cli; sleep 5
spd=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 40 -x socks5h://${PFX}c:1080 http://${PFX}big/f -o /dev/null -w '%{speed_download}' 2>/dev/null)
spd=${spd%.*}
b=FAIL; [ -n "$spd" ] && [ "$spd" -ge 1400000 ] && [ "$spd" -le 3200000 ] && b=PASS
echo "  实测速率=${spd} B/s(期望 ≈2097152,容差 1.4M~3.2M)   [rate 限速]  $b"
[ "$a" = FAIL -o "$b" = FAIL ] && docker logs ${PFX}s 2>&1|tail -4|sed 's/^/  SRV:/'
cleanup; echo DONE