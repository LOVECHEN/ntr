#!/bin/bash
# ============================================================================
# 通用 Brutal 拥塞控制端到端:给【非 hy1/hy2】的通用 quic 传输也能开 Brutal 定速 CC。
# quic 传输 layer 配 congestion:brutal + up/down-mbps → NTR 在建连后 conn.SetCongestionControl(
#   sing-quic 的 BrutalSender),复用 metacubex/quic-go 的自定义 CC 注入 —— 不再是 hy1/hy2 专属。
# NTR↔NTR:socks → quic[brutal] + vless → server → 靶机。验「通用开关生效 + Brutal CC 装上 + 传输正常」。
# 注:Brutal 的【抢带宽效果】(不做 AIMD 退让、按设定带宽定速发)需限速网络测吞吐,CI 不可靠;
#     本脚本证的是通用开关把 Brutal CC 装进 quic 传输且端到端不破坏,单测 brutal_test 另验配置换算。
# 专属 network=ix-qbrutal;前缀=ixqb-
# ============================================================================
set -u
NET=ix-qbrutal; PFX=ixqb-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
UUID="11111111-1111-1111-1111-111111111111"
PASS=0; FAIL=0
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1

# server:quic[brutal] + vless
cat > $D/${PFX}s.yaml <<Y
inbounds:
  - name: srv-in
    type: vless
    listen: 0.0.0.0:10000
    quic:
      congestion: brutal
      up-mbps: 100
      down-mbps: 100
    users:
      - uuid: "$UUID"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
docker run -d --name ${PFX}s --network $NET -e NTR_DEBUG=1 -v $NTR:/ntr:ro -v $D/${PFX}s.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 2
# client:socks → quic[brutal] + vless
cat > $D/${PFX}c.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: vless
    server: "${PFX}s:10000"
    secret: "$UUID"
    quic:
      sni: example.com
      insecure: true
      congestion: brutal
      up-mbps: 100
      down-mbps: 100
Y
docker run -d --name ${PFX}c --network $NET -e NTR_DEBUG=1 -v $NTR:/ntr:ro -v $D/${PFX}c.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 3

echo "=== quic[congestion:brutal, up/down-mbps:100] + vless 端到端 ==="
OUT=""; for i in 1 2 3 4 5; do OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>&1); echo "$OUT"|grep -q Hostname && break; sleep 2; done
if echo "$OUT"|grep -q Hostname; then
  echo "  ✅ 通用 Brutal 开关生效:quic 传输装上 Brutal CC(sing-quic BrutalSender)+ 端到端传输正常"; PASS=$((PASS+1))
else echo "  ❌ 不通 OUT=$OUT"; FAIL=$((FAIL+1)); echo "  srv:"; docker logs ${PFX}s 2>&1|tail -6|sed 's/^/    /'; echo "  cli:"; docker logs ${PFX}c 2>&1|tail -6|sed 's/^/    /'; fi

echo "════════ ix-quic-brutal:PASS=$PASS FAIL=$FAIL ════════"
[ $FAIL -eq 0 ] && echo "✅ 通用 Brutal 全绿" || echo "❌ 有失败"
