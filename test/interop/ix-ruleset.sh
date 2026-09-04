#!/bin/bash
# rule-set 远程订阅验证:NTR 经 detour 拉取远程文本规则集(Surge/Clash 格式,你贴的 Loyalsoldier 那套)、
# 解析成 IPSet/DomainSet 分流。① 远程 ip-list(cncidr.txt)→ CN IP 命中 → block;② 远程 domain-list(google.txt)→ block。
set -u
NET=ixrs; PFX=ixrs-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
CURL=curlimages/curl:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-30} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
cleanup; docker network create $NET >/dev/null 2>&1
# ① 远程 ip-list:Loyalsoldier cncidr.txt(经 detour=direct 拉)→ CN IP 分流到 block
cat > $D/_rs.yaml <<Y
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
    - name: cnip
      behavior: ipcidr
      detour: direct
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/cncidr.txt"
    - name: goog
      behavior: domain
      detour: direct
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/google.txt"
  rules:
    - rule-set:
        - cnip
      to: block
    - rule-set:
        - goog
      to: block
Y
docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_rs.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
# 远程拉取在 Build 期,给足时间(拉两个 CDN 文件)
if ! wait_log ${PFX}c "监听于" 40; then echo "  [启动/远程拉取失败]  FAIL"; docker logs ${PFX}c 2>&1|tail -4|sed 's/^/  NTR:/'; cleanup; echo DONE; exit 0; fi
R1=$(docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://223.5.5.5/ 2>&1)
echo "  [① 远程 ip-list(cncidr)→ CN(223.5.5.5)→ block]  $([ "$R1" = "000" ] && echo PASS || echo "FAIL(http=$R1)")"
R2=$(docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://adservice.google.com/ 2>&1)
echo "  [② 远程 domain-list(google)→ adservice.google.com → block]  $([ "$R2" = "000" ] && echo PASS || echo "FAIL(http=$R2)")"
R3=$(docker run --rm --network $NET $CURL -s --max-time 10 -o /dev/null -w '%{http_code}' -x socks5h://${PFX}c:1080 http://1.1.1.1/ 2>&1)
echo "  [③ 非CN非google(1.1.1.1)→ direct 放行]  $([ "$R3" != "000" ] && echo PASS || echo "FAIL(http=$R3)")"
cleanup; echo DONE
