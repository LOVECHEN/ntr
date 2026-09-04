#!/bin/bash
# 策略组(select/urltest/fallback/load-balance)行为验证 —— NTR 自有客户端分流特性,组是顶层出站类型。
# ① select:默认成员=direct → 流量经组落地到 whoami。② fallback:首成员=dead(TEST-NET 不可达)→ 探测标死 →
# 选中 direct → 仍通(证 fallback 跳过 dead)。选路是纯本地策略、wire 不可见,不涉任何协议线格式。
set -u
NET=ixgrp; PFX=ixgrp-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
CURL=curlimages/curl:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami --name GRP-TARGET >/dev/null 2>&1
sleep 1

# ① select 组:default=direct
cat > $D/_grp1.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: grp
outbounds:
  - name: grp
    type: select
    default: direct
    outbounds:
      - direct
      - blk
  - name: direct
    type: direct
  - name: blk
    type: block
Y
docker run -d --name ${PFX}c1 --network $NET -v $NTR:/ntr:ro -v $D/_grp1.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}c1 "监听于" 15
R1=$(docker run --rm --network $NET $CURL -s --max-time 10 -x socks5h://${PFX}c1:1080 http://${PFX}target/ 2>&1)
echo "  [① select 组 default=direct → 落地 whoami]  $(echo "$R1"|grep -q 'Name: GRP-TARGET' && echo PASS || echo FAIL)"
docker rm -f ${PFX}c1 >/dev/null 2>&1

# ② fallback 组:首成员 dead(TEST-NET 192.0.2.1 不可达)→ 探测标死 → 选 direct
cat > $D/_grp2.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: fb
outbounds:
  - name: fb
    type: fallback
    interval: 3s
    outbounds:
      - dead
      - direct
  - name: dead
    type: trojan
    server: "192.0.2.1:9"
    secret: "x"
    tls:
      sni: a
      insecure: true
  - name: direct
    type: direct
Y
docker run -d --name ${PFX}c2 --network $NET -v $NTR:/ntr:ro -v $D/_grp2.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}c2 "监听于" 15
sleep 6 # 等首轮健康探测(标死 dead、选中 direct)
R2=$(docker run --rm --network $NET $CURL -s --max-time 12 -x socks5h://${PFX}c2:1080 http://${PFX}target/ 2>&1)
echo "  [② fallback 组跳过 dead → 经 direct 落地 whoami]  $(echo "$R2"|grep -q 'Name: GRP-TARGET' && echo PASS || echo FAIL)"

cleanup; echo DONE
