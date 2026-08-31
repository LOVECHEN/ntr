#!/bin/bash
# ============================================================================
# TUN auto-route 端到端:NTR 启动 TUN 时【自动】配 split-default 路由(0.0.0.0/1 + 128.0.0.0/1
# dev tun,覆盖全部出站、不动系统 default),把流量导入 tun —— 无需像 ix-tun 那样手动 ip route add。
# 排除代理服务器 IP(经原默认网关直连,防「拨代理」的流量又被捕获 → 回环)。
# 拓扑:TUN 容器(前端网 NF)—— curl 后端网 NB 的靶机 W(NF 直连够不到)→ auto-route 导入 tun
#       → netstack → proxy 出站 → 网关 P(跨 NF/NB,exclude 直连)→ direct → W。
# 判据:① ip route 自动出现 0.0.0.0/1 dev ntr-tun0;② curl W【全程不手动加路由】通 +
#       RemoteAddr==P(证流量确经 tun→proxy 落地,而非本地直连)。
# 需 -tags with_tun;容器 --cap-add NET_ADMIN + /dev/net/tun + iproute2(auto-route 用 ip)。
# 专属 network=ix-arf/ix-arb;前缀=ixar-
# ============================================================================
set -u
NET_F=ix-arf; NET_B=ix-arb; PFX=ixar-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
PASS=0; FAIL=0
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET_F $NET_B >/dev/null 2>&1; }
trap cleanup EXIT
cleanup; docker network create $NET_F >/dev/null 2>&1; docker network create $NET_B >/dev/null 2>&1

# W 靶机:仅后端网(TUN 容器前端网直连够不到,只能经 proxy)
docker run -d --name ${PFX}target --network $NET_B traefik/whoami >/dev/null 2>&1
# P 网关代理:前端网起 + 接后端网(跨网,socks→direct)
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}\noutbounds: [{name: direct, type: direct}]\n' > $D/${PFX}p.yaml
docker run -d --name ${PFX}p --network $NET_F -v $NTR:/ntr:ro -v $D/${PFX}p.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
docker network connect $NET_B ${PFX}p
sleep 1
PIP=$(docker inspect ${PFX}p --format "{{(index .NetworkSettings.Networks \"$NET_F\").IPAddress}}")
WIP=$(docker inspect ${PFX}target --format "{{(index .NetworkSettings.Networks \"$NET_B\").IPAddress}}")
PBIP=$(docker inspect ${PFX}p --format "{{(index .NetworkSettings.Networks \"$NET_B\").IPAddress}}")
echo "P(NF)=$PIP  P(NB)=$PBIP  W(NB)=$WIP"

# TUN 容器:auto-route: true + route-exclude=[P],出站 proxy→P。装 iproute2(auto-route 用 ip)
cat > $D/${PFX}tun.yaml <<EOF
inbounds:
  - type: tun
    if-name: ntr-tun0
    address: [10.9.9.1/24]
    mtu: 1500
    auto-route: true
    route-exclude: ["$PIP"]
    outbound: up
outbounds:
  - {name: up, type: proxy, server: "$PIP:1080", layers: [{type: socks}]}
  - {name: direct, type: direct}
EOF
docker run -d --name ${PFX}tun --network $NET_F --cap-add NET_ADMIN --device /dev/net/tun -e NTR_DEBUG=1 \
  -v $NTR:/ntr:ro -v $D/${PFX}tun.yaml:/c.yaml:ro alpine sh -c 'apk add --no-cache iproute2 curl >/dev/null 2>&1; exec /ntr -config /c.yaml' >/dev/null 2>&1
# 等 apk 装完 iproute2/curl + NTR auto-route 就绪(冷 runner 上 apk 下载较慢)
for i in $(seq 1 15); do docker exec ${PFX}tun ip route show 2>/dev/null | grep -q "0.0.0.0/1" && break; sleep 1; done

# ① auto-route 自动配的路由(无需手动 ip route add)
echo "=== ① auto-route 自动配 split-default 路由 ==="
echo "  [完整 ip route]"; docker exec ${PFX}tun ip route show 2>&1 | sed 's/^/    /'
echo "  [NTR 日志尾]"; docker logs ${PFX}tun 2>&1 | tail -5 | sed 's/^/    /'
RT=$(docker exec ${PFX}tun ip route show 2>/dev/null)
echo "$RT" | grep -E "0.0.0.0/1|128.0.0.0/1|$PIP" | sed 's/^/  /'
if echo "$RT" | grep -qE "0.0.0.0/1[ ].*ntr-tun0"; then
  echo "  ✅ split-default 0.0.0.0/1 dev ntr-tun0 已自动配(未手动 ip route)"; PASS=$((PASS+1))
else echo "  ❌ 未见 auto-route 路由"; FAIL=$((FAIL+1)); docker logs ${PFX}tun 2>&1|tail -10|sed 's/^/  /'; fi

# ② curl W【全程不手动加路由】→ 经 tun → proxy → W
echo "=== ② curl 后端靶机 W(不手动加路由)→ 经 tun→proxy→W ==="
OUT=""; for i in 1 2 3 4 5 6; do OUT=$(docker exec ${PFX}tun curl -s --max-time 8 http://$WIP/ 2>/dev/null); echo "$OUT"|grep -q Hostname && break; sleep 2; done
RA=$(echo "$OUT" | grep -i RemoteAddr | sed 's/.*RemoteAddr: //; s/:[0-9]*$//')
echo "  靶机看到来源=$RA(期望 P 的后端 IP $PBIP)"
if echo "$OUT"|grep -q Hostname && [ "$RA" = "$PBIP" ]; then
  echo "  ✅ auto-route 生效:curl W 全程未手动加路由,自动经 tun→proxy 落地(RemoteAddr==P)"; PASS=$((PASS+1))
else echo "  ❌ 不通 OUT=$OUT"; FAIL=$((FAIL+1)); docker logs ${PFX}tun 2>&1|tail -10|sed 's/^/  /'; fi

echo "════════ ix-tun-autoroute:PASS=$PASS FAIL=$FAIL ════════"
[ $FAIL -eq 0 ] && echo "✅ TUN auto-route 全绿" || echo "❌ 有失败"
