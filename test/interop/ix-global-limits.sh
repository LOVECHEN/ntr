#!/bin/bash
# 全局 / 每口限制验证(承设计 §6.2 层1/2)。叠加顺序 全局→口→用户,任一超即拒(§6.2.2)。
#   A. 全局 max-conns=2:2 条慢下载占满 → 第 3 条(哪怕不同口/用户)被拒。
#   B. 全局 rate=16mbps:下载吞吐 ≈ 2MiB/s。
# 用 socks 入站(无需按用户计量;全局闸独立于 metering)。
set -u
NET=ix-glim; PFX=ixglim-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}big --network $NET python:3-alpine sh -c "python3 -c \"open('/f','wb').write(b'x'*20971520)\"; cd /; python3 -m http.server 80" >/dev/null 2>&1
docker run -d --name ${PFX}who --network $NET traefik/whoami >/dev/null 2>&1
sleep 1
start(){ # $1 = limits-block
  docker rm -f ${PFX}s >/dev/null 2>&1
  cat > $D/_glim.yaml <<Y
$1
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}
outbounds: [{name: direct, type: direct}]
Y
  docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_glim.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 2
}

echo "=== A. 全局 max-conns=2 ==="
start 'limits: {max-conns: 2}'
for i in 1 2; do docker run -d --name ${PFX}dl$i --network $NET curlimages/curl:latest -s --max-time 60 --limit-rate 150k -x socks5h://${PFX}s:1080 http://${PFX}big/f -o /dev/null >/dev/null 2>&1; done
sleep 4
r3=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 -x socks5h://${PFX}s:1080 http://${PFX}who/ 2>/dev/null | grep -c Hostname)
a=$([ "$r3" = 0 ] && echo PASS || echo FAIL)
echo "  第3条(全局)接入=$([ "$r3" = 0 ] && echo 被拒 || echo 通过)   [全局 max-conns=2]  $a"
docker rm -f ${PFX}dl1 ${PFX}dl2 >/dev/null 2>&1

echo "=== B. 全局 rate=16mbps,下载 20MiB ==="
start 'limits: {rate: 16mbps}'
spd=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 40 -x socks5h://${PFX}s:1080 http://${PFX}big/f -o /dev/null -w '%{speed_download}' 2>/dev/null)
spd=${spd%.*}
b=$([ -n "$spd" ] && [ "$spd" -ge 1400000 ] && [ "$spd" -le 3200000 ] && echo PASS || echo FAIL)
echo "  实测速率=${spd} B/s(期望 ≈2097152)   [全局 rate 限速]  $b"
[ "$a" = FAIL -o "$b" = FAIL ] && docker logs ${PFX}s 2>&1|tail -4|sed 's/^/  SRV:/'
cleanup; echo DONE