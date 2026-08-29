#!/bin/bash
# 热开关验证(承设计 §6.5「用户随时上下线」):运行时 Disable/Enable 一个凭据。
# NTR vless 服务端(一个 uuid 用户)+ metrics 控制端点。经 NTR vless 客户端 curl:
#   ① 正常通 → /stats 读到该用户 id;② POST /disable?id → 断老 + 拒新(curl 失败);
#   ③ POST /enable?id → 恢复(curl 又通)。全程不改配置、不重启、不断其他连接。
set -u
NET=ix-hsw; PFX=ixhsw-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; UUID=11111111-2222-3333-4444-555555555555
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1
cat > $D/_hsw_srv.yaml <<Y
metrics: {listen: 0.0.0.0:9091, access: ["0.0.0.0/0"]}
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: vless}]
    users: [{uuid: "$UUID"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
cat > $D/_hsw_cli.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", secret: "$UUID", layers: [{type: vless}]}
Y
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_hsw_srv.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_hsw_cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 2
S=$(docker inspect ${PFX}s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)

cput(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 "$@" 2>/dev/null; }
pull(){ cput -x socks5h://${PFX}c:1080 http://${PFX}target/ | grep -qc Hostname; }

echo "=== ① 正常:curl 经 vless 用户 ==="
r1=$(cput -x socks5h://${PFX}c:1080 http://${PFX}target/ | grep -c Hostname)
[ "$r1" -ge 1 ] && echo "  通 PASS" || echo "  通 FAIL"

# 从 /stats 读该用户 id(排除 Ambient=1;取有流量的用户槽)
stats=$(cput http://$S:9091/stats)
echo "  /stats: $stats"
ID=$(echo "$stats" | grep -oE '"id":[0-9]+' | grep -oE '[0-9]+' | awk '$1>1{print;exit}')
[ -z "$ID" ] && ID=$(echo "$stats" | grep -oE '"id":[0-9]+' | grep -oE '[0-9]+' | head -1)
echo "  用户槽 id=$ID"

echo "=== ② POST /disable?id=$ID(拒新 + 断老)==="
ack=$(cput -X POST "http://$S:9091/disable?id=$ID"); echo "  回执: $ack"
sleep 1
r2=$(cput -x socks5h://${PFX}c:1080 http://${PFX}target/ | grep -c Hostname)
[ "$r2" -eq 0 ] && echo "  [停用后 curl 被拒]  PASS" || echo "  [停用后 curl 被拒]  FAIL(仍通)"
d=$(cput http://$S:9091/stats | grep -oE '"disabled":true' | head -1)
[ -n "$d" ] && echo "  /stats disabled=true ✓"

echo "=== ③ POST /enable?id=$ID(恢复)==="
cput -X POST "http://$S:9091/enable?id=$ID" >/dev/null
sleep 1
r3=$(cput -x socks5h://${PFX}c:1080 http://${PFX}target/ | grep -c Hostname)
[ "$r3" -ge 1 ] && echo "  [恢复后 curl 又通]  PASS" || echo "  [恢复后 curl 又通]  FAIL"
[ "$r2" -eq 0 -a "$r3" -ge 1 ] && echo "  === 用户随时上下线 验证通过 ===" || { docker logs ${PFX}s 2>&1|tail -4|sed 's/^/  SRV:/'; docker logs ${PFX}c 2>&1|tail -3|sed 's/^/  CLI:/'; }
cleanup; echo DONE