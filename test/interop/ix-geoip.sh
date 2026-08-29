#!/bin/bash
# geoip 分流验证:NTR 按目标 IP 归属国分流。用真 GeoLite2-Country.mmdb(MaxMind 格式,mihomo 同款 → 同一 DB
# 即同一裁决,天然可对 mihomo 交叉验证)。规则 geoip:[CN]→block,default→direct;
# ① 223.5.5.5(AliDNS,CN)→ 命中 CN → block → 拿不到响应;② 1.1.1.1(Cloudflare,非CN)→ direct → 有响应。
set -u
NET=ixgeo; PFX=ixgeo-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
CURL=curlimages/curl:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
# 下载 GeoLite2-Country.mmdb(LOVECHEN 镜像;失败退 P3TERX)
if [ ! -s "$D/geoip.mmdb" ]; then
  docker run --rm --network host -v $D:/w $CURL -sL -o /w/geoip.mmdb \
    "https://github.com/LOVECHEN/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb" 2>/dev/null
  [ -s "$D/geoip.mmdb" ] || docker run --rm --network host -v $D:/w $CURL -sL -o /w/geoip.mmdb \
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb" 2>/dev/null
fi
[ -s "$D/geoip.mmdb" ] || { echo "  [下载 geoip.mmdb 失败]  FAIL"; echo DONE; exit 0; }
cleanup; docker network create $NET >/dev/null 2>&1
cat > $D/_geo.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}]
outbounds:
  - {name: direct, type: direct}
  - {name: block, type: block}
routing:
  default: direct
  geoip-path: /geoip.mmdb
  rules:
    - {geoip: [CN], to: block}
Y
docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_geo.yaml:/c.yaml:ro -v $D/geoip.mmdb:/geoip.mmdb:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}c "监听于" 15
# ① CN IP → block(应拿不到响应);curl 到 223.5.5.5:80(AliDNS 有 HTTP 落地页)
R1=$(docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://223.5.5.5/ 2>&1)
echo "  [① geoip CN(223.5.5.5)→ block]  $([ "$R1" = "000" ] && echo PASS || echo "FAIL(http=$R1)")"
# ② 非CN IP → direct(应有响应);1.1.1.1 Cloudflare 有 HTTP
R2=$(docker run --rm --network $NET $CURL -s --max-time 10 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://1.1.1.1/ 2>&1)
echo "  [② 非CN(1.1.1.1)→ direct 放行]  $([ "$R2" != "000" ] && echo PASS || echo "FAIL(http=$R2)")"
cleanup; echo DONE
