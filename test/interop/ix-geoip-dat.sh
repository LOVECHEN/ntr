#!/bin/bash
# geoip.dat 分流验证:NTR 用 V2Ray/Xray 的 geoip.dat(protobuf,非 mmdb)按目标 IP 归属国分流。
# 用真 Loyalsoldier v2ray-rules-dat 的 geoip.dat(Xray/sing-box/mihomo 同款库 → 同一裁决,天然可交叉验证)。
# 规则 geoip:[CN]→block,default→direct(geoip-path 指 .dat,config 按后缀自动走 protobuf 解析器)。
# ① 223.5.5.5(AliDNS,CN)→ 命中 CN → block;② 1.1.1.1(Cloudflare,非CN)→ direct → 有响应。
set -u
NET=ixgeodat; PFX=ixgeodat-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
CURL=curlimages/curl:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
# 优先宿主原生 curl(CI runner / macOS 都有),失败退 docker
fetch(){ command -v curl >/dev/null 2>&1 && curl -fsSL --max-time 60 -o "$1" "$2" 2>/dev/null && [ -s "$1" ] && return 0; docker run --rm --network host -v $D:/w $CURL -fsSL --max-time 60 -o "/w/$(basename "$1")" "$2" 2>/dev/null; [ -s "$1" ]; }
# 下载 geoip.dat(Loyalsoldier v2ray-rules-dat;失败退 jsdelivr CDN)
if [ ! -s "$D/geoip.dat" ]; then
  fetch "$D/geoip.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" ||
  fetch "$D/geoip.dat" "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
fi
[ -s "$D/geoip.dat" ] || { echo "  [下载 geoip.dat 失败]  FAIL"; echo DONE; exit 0; }
cleanup; docker network create $NET >/dev/null 2>&1
cat > $D/_geodat.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}]
outbounds:
  - {name: direct, type: direct}
  - {name: block, type: block}
routing:
  default: direct
  geoip-path: /geoip.dat
  rules:
    - {geoip: [CN], to: block}
Y
docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_geodat.yaml:/c.yaml:ro -v $D/geoip.dat:/geoip.dat:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}c "监听于" 15
# ① CN IP → block(应拿不到响应)
R1=$(docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://223.5.5.5/ 2>&1)
echo "  [① geoip.dat CN(223.5.5.5)→ block]  $([ "$R1" = "000" ] && echo PASS || echo "FAIL(http=$R1)")"
# ② 非CN IP → direct(应有响应)
R2=$(docker run --rm --network $NET $CURL -s --max-time 10 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://1.1.1.1/ 2>&1)
echo "  [② 非CN(1.1.1.1)→ direct 放行]  $([ "$R2" != "000" ] && echo PASS || echo "FAIL(http=$R2)")"
cleanup; echo DONE
