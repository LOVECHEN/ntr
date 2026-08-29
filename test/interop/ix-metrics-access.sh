#!/bin/bash
# 管理端点访问控制验证:含 Disable/Kill 权力,故默认【仅本机】,access 白名单显式放开。
#   ① 默认(无 access):本机(容器内 127.0.0.1)可访问;跨容器源 IP → 403
#   ② access:[docker 网段] → 跨容器可访问
#   ③ access:[0.0.0.0/0] → 全开(慎用)
set -u
NET=ix-macc; PFX=ixmacc-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1

start(){ # $1=access-yaml(可空)
  docker rm -f ${PFX}s >/dev/null 2>&1
  cat > $D/_macc.yaml <<Y
metrics:
  listen: 0.0.0.0:9091
$1
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}
outbounds: [{name: direct, type: direct}]
Y
  docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_macc.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 2
}
S(){ docker inspect ${PFX}s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null; }
code_from_other(){ docker run --rm --network $NET curlimages/curl:latest -s -o /dev/null -w '%{http_code}' --max-time 5 http://$(S):9091/stats 2>/dev/null; }
code_from_local(){ docker exec ${PFX}s sh -c 'wget -qO- --timeout=5 http://127.0.0.1:9091/stats >/dev/null 2>&1 && echo 200 || echo ERR' 2>/dev/null; }

echo "=== ① 默认(仅本机)==="
start ""
echo "  本机(127.0.0.1)访问码: $(code_from_local)   跨容器访问码: $(code_from_other)"
a=$( [ "$(code_from_other)" = "403" ] && echo PASS || echo FAIL )
echo "  [默认跨容器被拒 403]  $a"

echo "=== ② access:[docker 网段] ==="
GW=$(docker network inspect $NET --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)
start "  access: [\"$GW\"]"
c=$(code_from_other)
b=$( [ "$c" = "200" ] && echo PASS || echo FAIL )
echo "  网段=$GW 跨容器访问码=$c   [白名单网段放行]  $b"

echo "=== ③ access:[0.0.0.0/0](全开)==="
start "  access: [\"0.0.0.0/0\"]"
c=$(code_from_other)
d=$( [ "$c" = "200" ] && echo PASS || echo FAIL )
echo "  全开访问码=$c   [0.0.0.0/0 全放行]  $d"
cleanup; echo DONE