#!/bin/bash
# sing-box .srs 二进制规则集互通:sing-box 亲自把源规则集编成 .srs(domain succinct matcher + ip_cidr 区间),
# NTR 直接加载(魔数 "SRS" 自动识别)、解出 DomainSet/IPSet 分流。证 NTR 读得懂 sing-box 的二进制库。
# ① domain .srs(domain_suffix example.com)→ example.com/子域 → block;② ip_cidr .srs(223.5.5.0/24)→ 223.5.5.5 → block;
# ③ 非集内(1.1.1.1)→ direct 放行。
set -u
NET=ixsrs; PFX=ixsrs-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
CURL=curlimages/curl:latest; SB=ghcr.io/sagernet/sing-box:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-30} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
# sing-box 源规则集 → .srs(domain + ip 两个)
cat > $D/_sdom.json <<J
{"version":1,"rules":[{"domain_suffix":["example.com"]}]}
J
cat > $D/_sip.json <<J
{"version":1,"rules":[{"ip_cidr":["223.5.5.0/24"]}]}
J
docker run --rm -v $D:/w -w /w $SB rule-set compile --output _dom.srs _sdom.json >/dev/null 2>&1
docker run --rm -v $D:/w -w /w $SB rule-set compile --output _ip.srs _sip.json >/dev/null 2>&1
[ -s "$D/_dom.srs" ] && [ -s "$D/_ip.srs" ] || { echo "  [sing-box 生成 .srs 失败]  FAIL"; echo DONE; exit 0; }
cleanup; docker network create $NET >/dev/null 2>&1
cat > $D/_srs.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: direct
outbounds:
  - name: direct
    type: direct
  - name: block
    type: block
routing:
  default: direct
  rule-providers:
    - name: sdom
      behavior: domain
      path: /dom.srs
    - name: sip
      behavior: ipcidr
      path: /ip.srs
  rules:
    - rule-set:
        - sdom
      to: block
    - rule-set:
        - sip
      to: block
Y
docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_srs.yaml:/c.yaml:ro -v $D/_dom.srs:/dom.srs:ro -v $D/_ip.srs:/ip.srs:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
if ! wait_log ${PFX}c "监听于" 20; then echo "  [NTR 加载 .srs 失败]  FAIL"; docker logs ${PFX}c 2>&1|tail -4|sed 's/^/  NTR:/'; cleanup; echo DONE; exit 0; fi
# sing domain_suffix example.com → 匹配子域 www.example.com(sing 后缀语义:apex 也算,这里用子域最稳)
R1=$(docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://www.example.com/ 2>&1)
echo "  [① sing-box domain .srs → www.example.com → block]  $([ "$R1" = "000" ] && echo PASS || echo "FAIL(http=$R1)")"
R2=$(docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://223.5.5.5/ 2>&1)
echo "  [② sing-box ip_cidr .srs → 223.5.5.5 → block]  $([ "$R2" = "000" ] && echo PASS || echo "FAIL(http=$R2)")"
R3=$(docker run --rm --network $NET $CURL -s --max-time 10 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://1.1.1.1/ 2>&1)
echo "  [③ 非集内(1.1.1.1)→ direct 放行]  $([ "$R3" != "000" ] && echo PASS || echo "FAIL(http=$R3)")"
cleanup; echo DONE
