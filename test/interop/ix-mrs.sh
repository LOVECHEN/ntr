#!/bin/bash
# mihomo .mrs 二进制规则集互通:mihomo 亲自把文本编成 .mrs(domain succinct-trie + ipcidr 区间集),
# NTR 直接加载(魔数自动识别 zstd→.mrs)、解出 DomainSet/IPSet 分流。证 NTR 读得懂 mihomo 的二进制库。
# ① domain .mrs(含 example.com)→ example.com → block;② ipcidr .mrs(含 223.5.5.0/24)→ 223.5.5.5 → block;
# ③ 非集内(1.1.1.1)→ direct 放行。
set -u
NET=ixmrs; PFX=ixmrs-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
CURL=curlimages/curl:latest; MIHOMO=metacubex/mihomo:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-30} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
# mihomo 生成 .mrs(domain + ipcidr)
printf 'example.com\n' > $D/_mdom.txt
printf '223.5.5.0/24\n' > $D/_mip.txt
docker run --rm -v $D:/w $MIHOMO convert-ruleset domain text /w/_mdom.txt /w/_dom.mrs >/dev/null 2>&1
docker run --rm -v $D:/w $MIHOMO convert-ruleset ipcidr text /w/_mip.txt /w/_ip.mrs >/dev/null 2>&1
[ -s "$D/_dom.mrs" ] && [ -s "$D/_ip.mrs" ] || { echo "  [mihomo 生成 .mrs 失败]  FAIL"; echo DONE; exit 0; }
cleanup; docker network create $NET >/dev/null 2>&1
cat > $D/_mrs.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}]
outbounds:
  - {name: direct, type: direct}
  - {name: block, type: block}
routing:
  default: direct
  rule-providers:
    - {name: mdom, behavior: domain, path: /dom.mrs}
    - {name: mip, behavior: ipcidr, path: /ip.mrs}
  rules:
    - {rule-set: [mdom], to: block}
    - {rule-set: [mip], to: block}
Y
docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_mrs.yaml:/c.yaml:ro -v $D/_dom.mrs:/dom.mrs:ro -v $D/_ip.mrs:/ip.mrs:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
if ! wait_log ${PFX}c "监听于" 20; then echo "  [NTR 加载 .mrs 失败]  FAIL"; docker logs ${PFX}c 2>&1|tail -4|sed 's/^/  NTR:/'; cleanup; echo DONE; exit 0; fi
R1=$(docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://example.com/ 2>&1)
echo "  [① mihomo domain .mrs → example.com → block]  $([ "$R1" = "000" ] && echo PASS || echo "FAIL(http=$R1)")"
R2=$(docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://223.5.5.5/ 2>&1)
echo "  [② mihomo ipcidr .mrs → 223.5.5.5 → block]  $([ "$R2" = "000" ] && echo PASS || echo "FAIL(http=$R2)")"
R3=$(docker run --rm --network $NET $CURL -s --max-time 10 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://1.1.1.1/ 2>&1)
echo "  [③ 非集内(1.1.1.1)→ direct 放行]  $([ "$R3" != "000" ] && echo PASS || echo "FAIL(http=$R3)")"
cleanup; echo DONE
