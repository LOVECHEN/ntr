#!/bin/bash
# ============================================================================
# fake-ip 完整 TUN 端到端(承设计 §10.4:只见 IP 的连接按域名分流的【真实 TUN 场景】)。
# ix-fakeip 验的是 socks 路径;本脚本验完整 TUN 链路:
#   curl fake.test → DNS 查询进 TUN → dns-hijack :53 → resolver fake-ip 合成伪 IP(198.18/15)→
#   curl 连伪 IP → SYN 进 TUN → netstack → resolverOutbound 反查伪 IP→域名 fake.test →
#   routing 按域名分流 → socks 出站到网关 P → direct 解析 fake.test(docker alias)→ whoami。
# 反证:反查若失败,连伪 IP 时 socks 目标=伪 IP(不可路由)→ P 连不上 → curl 失败;故 curl 成功=全链路生效。
# 需 -tags with_tun;容器 --cap-add NET_ADMIN + /dev/net/tun。专属 network=ix-tunfip;前缀=ixtf-
# ============================================================================
set -u
NET=ix-tunfip; PFX=ixtf-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
PASS=0; FAIL=0
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
cleanup; docker network create $NET >/dev/null 2>&1

# 靶机 whoami,别名 fake.test(网关 direct 经 docker DNS 解析 fake.test → 靶机)
docker run -d --name ${PFX}target --network $NET --network-alias fake.test traefik/whoami >/dev/null 2>&1
sleep 1
W=$(docker inspect ${PFX}target --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "whoami W=$W (alias fake.test)"

# 网关 P:socks → direct(docker DNS 解析 fake.test → W)
cat > $D/_tf_gw.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
docker run -d --name ${PFX}gw --network $NET -v $NTR:/ntr:ro -v $D/_tf_gw.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 1
GWIP=$(docker inspect ${PFX}gw --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "网关 P=$GWIP:1080(up 出站用真实 IP —— TUN 下 resolv.conf 指向 hijack,若用域名 NTR 解析网关也会被 fake-ip 误伤)"

# TUN 容器:dns fake-ip + tun dns-hijack + routing(反查后的域名 → up socks → P)
cat > $D/_tf_tun.yaml <<Y
dns:
  enabled: true
  nameservers:
    - tag: up1
      address: "udp://1.1.1.1:53"
      detour: up
  fake-ip:
    enabled: true
    inet4-range: 198.18.0.0/15
inbounds:
  - name: tun-in
    type: tun
    if-name: ntr-tun0
    address:
      - 10.9.9.1/24
    mtu: 1500
    dns-hijack:
      - "any:53"
    outbound: up
routing:
  default: up
  rules:
    - domain-suffix:
        - fake.test
      to: up
outbounds:
  - name: up
    type: socks
    server: "$GWIP:1080"
  - name: direct
    type: direct
Y
docker run -d --name ${PFX}tun --network $NET --cap-add NET_ADMIN --device /dev/net/tun -e NTR_DEBUG=1 \
  -v $NTR:/ntr:ro -v $D/_tf_tun.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 3

# 等 tun 网卡就绪,装工具,路由:伪 IP 段 + DNS IP 进 tun;resolv.conf 指向该 DNS IP
docker exec ${PFX}tun sh -c 'apk add -q iproute2 curl bind-tools >/dev/null 2>&1; for i in 1 2 3 4 5 6; do ip link show ntr-tun0 >/dev/null 2>&1 && break; sleep 1; done'
docker exec ${PFX}tun sh -c "
  ip route add 198.18.0.0/15 dev ntr-tun0 2>&1
  ip route add 10.0.0.53/32 dev ntr-tun0 2>&1
  echo 'nameserver 10.0.0.53' > /etc/resolv.conf
  echo '  路由:伪IP段 198.18/15 + DNS 10.0.0.53 → tun;resolv.conf → 10.0.0.53'
"

# ① DNS hijack + fake-ip:dig fake.test 经 tun 得伪 IP
echo "=== ① DNS hijack + fake-ip 合成 ==="
FE=""
for i in 1 2 3 4 5; do
  FE=$(docker exec ${PFX}tun sh -c "dig +short +time=4 fake.test A @10.0.0.53 2>/dev/null | grep -E '^198\.1[89]\.' | head -1")
  [ -n "$FE" ] && break; sleep 1
done
if [ -n "$FE" ]; then echo "  ✅ fake.test → 伪 IP $FE"; PASS=$((PASS+1)); else echo "  ❌ 无伪 IP(hijack/fakeip 未生效)"; FAIL=$((FAIL+1)); fi

# ② 完整链路:curl fake.test → 伪IP → 反查 → 分流 → whoami
echo "=== ② 完整 TUN 链路 curl fake.test ==="
ok=""
for i in 1 2 3 4 5 6; do
  r=$(docker exec ${PFX}tun curl -s --max-time 8 http://fake.test/ 2>/dev/null)
  echo "$r" | grep -q Hostname && { ok=1; break; }
  sleep 1
done
if [ -n "$ok" ]; then echo "  ✅ curl fake.test 拿到 Hostname(域名→伪IP→反查→按域名分流→whoami 全链路)"; PASS=$((PASS+1))
else echo "  ❌ curl fake.test 失败"; FAIL=$((FAIL+1))
  echo "  --- 诊断 ---"
  echo "  [alias fake.test 可解?]"; docker run --rm --network $NET alpine sh -c 'nslookup fake.test 2>&1 | tail -3' | sed 's/^/    /'
  echo "  [路由 $FE]"; docker exec ${PFX}tun ip route get "$FE" 2>&1 | sed 's/^/    /'
  echo "  [curl -v 伪 IP $FE 看连接阶段]"; docker exec ${PFX}tun sh -c "curl -sv --max-time 6 http://$FE/ 2>&1 | grep -iE 'trying|connected to|timed|refused|empty|closing|HTTP/' | head -6" | sed 's/^/    /'
  echo "  [网关直连 fake.test(P 侧 direct 解析)]"; docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 -x socks5h://${PFX}gw:1080 http://fake.test/ 2>&1 | grep -E 'Hostname|curl' | head -2 | sed 's/^/    /'
  docker logs ${PFX}tun 2>&1|tail -12|sed 's/^/  TUN:/'; docker logs ${PFX}gw 2>&1|tail -4|sed 's/^/  GW:/'; fi

echo "════════ ix-tun-fakeip:PASS=$PASS FAIL=$FAIL ════════"
[ $FAIL -eq 0 ] && echo "✅ fake-ip 完整 TUN 端到端全绿" || echo "❌ 有失败"
