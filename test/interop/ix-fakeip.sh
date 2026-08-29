#!/bin/bash
# fake-ip 验证:NTR 的 DNS 入站给域名发伪 IP,socks 入站收到伪 IP 时反查回域名再按规则分流。
# 证「只见 IP 的连接也能按域名分流」这条 fake-ip 的核心价值,不需 TUN(纯 DNS+socks 即可验)。
# ① nslookup example.com @NTR → 得 198.18/198.19 伪 IP(合成生效);
# ② curl 该伪 IP 经 NTR socks → example.com 命中 block 规则 → 000(反查→域名→分流);
# ③ nslookup 靶机名 @NTR → 另一伪 IP;curl 它经 socks → 反查→直连 docker DNS→whoami → 200(非阻塞路径)。
set -u
NET=ixfip; PFX=ixfip-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
CURL=curlimages/curl:latest; ALP=alpine:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
fakeip(){ docker run --rm --network $NET $ALP nslookup "$1" ${PFX}ntr 2>/dev/null | grep -oE '198\.1[89]\.[0-9]+\.[0-9]+' | tail -1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}whoami --network $NET traefik/whoami >/dev/null 2>&1
cat > $D/_fakeip.yaml <<Y
dns:
  enabled: true
  detour: direct
  nameservers:
    - {tag: up, address: udp://1.1.1.1:53, detour: direct}
  fake-ip:
    enabled: true
    inet4-range: 198.18.0.0/15
inbounds:
  - {listen: 0.0.0.0:53, type: dns}
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}
outbounds:
  - {name: direct, type: direct}
  - {name: block, type: block}
routing:
  default: direct
  rules:
    - {domain-suffix: [example.com], to: block}
Y
docker run -d --name ${PFX}ntr --network $NET -v $NTR:/ntr:ro -v $D/_fakeip.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
if ! wait_log ${PFX}ntr "监听于" 15; then echo "  [NTR 启动失败]  FAIL"; docker logs ${PFX}ntr 2>&1|tail -4|sed 's/^/  NTR:/'; cleanup; echo DONE; exit 0; fi
# ① 合成:example.com → 伪 IP
FE=$(fakeip example.com)
echo "  [① DNS 入站 fake-ip 合成 example.com → $FE]  $([ -n "$FE" ] && echo PASS || echo FAIL)"
# ② 反查→block:curl 伪 IP 经 socks → example.com 命中 block
if [ -n "$FE" ]; then
  R2=$(docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}ntr:1080 "http://$FE/" 2>&1)
  echo "  [② 伪 IP 反查 example.com → block]  $([ "$R2" = "000" ] && echo PASS || echo "FAIL(http=$R2)")"
else echo "  [② 跳过:无伪 IP]  FAIL"; fi
# ③ 非阻塞:靶机域名 → 伪 IP → 反查直连 → whoami 200
FW=$(fakeip ${PFX}whoami)
if [ -n "$FW" ]; then
  R3=$(docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}ntr:1080 "http://$FW/" 2>&1)
  echo "  [③ 伪 IP 反查靶机 → direct → 200]  $([ "$R3" = "200" ] && echo PASS || echo "FAIL(http=$R3)")"
else echo "  [③ 跳过:无伪 IP]  FAIL"; fi
cleanup; echo DONE
