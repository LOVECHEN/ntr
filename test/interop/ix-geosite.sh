#!/bin/bash
# geosite 分流验证:NTR 按目标域名的 geosite 类目分流。用真 geosite.dat(V2Ray/mihomo 格式,同 DB 同裁决 → 可对 mihomo 验)。
# geosite:[google]→block,default→direct;① www.google.com(∈google)→ block ② example.com(∉)→ direct 放行。
set -u
NET=ixgs; PFX=ixgs-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
CURL=curlimages/curl:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
if [ ! -s "$D/geosite.dat" ]; then
  docker run --rm --network host -v $D:/w $CURL -sL -o /w/geosite.dat \
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat" 2>/dev/null
fi
[ -s "$D/geosite.dat" ] || { echo "  [下载 geosite.dat 失败]  FAIL"; echo DONE; exit 0; }
cleanup; docker network create $NET >/dev/null 2>&1
cat > $D/_gs.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}]
outbounds:
  - {name: direct, type: direct}
  - {name: block, type: block}
routing:
  default: direct
  geosite-path: /geosite.dat
  rules:
    - {geosite: [google], to: block}
Y
docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_gs.yaml:/c.yaml:ro -v $D/geosite.dat:/geosite.dat:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}c "监听于" 15
R1=$(docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://www.google.com/ 2>&1)
echo "  [① geosite google(www.google.com)→ block]  $([ "$R1" = "000" ] && echo PASS || echo "FAIL(http=$R1)")"
R2=$(docker run --rm --network $NET $CURL -s --max-time 10 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://example.com/ 2>&1)
echo "  [② 非google(example.com)→ direct 放行]  $([ "$R2" != "000" ] && echo PASS || echo "FAIL(http=$R2)")"
cleanup; echo DONE
