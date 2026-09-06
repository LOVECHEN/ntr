#!/bin/bash
# 崩点1(§8.3.5 resolve-for-routing)e2e:域名目标 + 只配 ip-cidr 规则 → NTR 按需解析域名真 IP 再匹配 ip 规则。
# 修复前:域名目标【静默跳过】ip-cidr/geoip → block 域名会漏过、直连(泄漏)。修复后:LookupReal 解出真 IP → 命中 cidr → block。
# 拨号 dst 仍是域名(伪 IP/解析只喂路由决策,不出本机)。DNS 走容器内嵌 DNS(127.0.0.11)detour=direct。
set -u
NET=ix-rr; PFX=ixrr-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}allow --network $NET traefik/whoami >/dev/null 2>&1
docker run -d --name ${PFX}block --network $NET traefik/whoami >/dev/null 2>&1
sleep 1
BLOCKIP=$(docker inspect ${PFX}block --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
# ★关键:routing 只有 ip-cidr 规则、无 domain 规则。dns: 让 NTR 能解析域名(经内嵌 DNS,detour=direct 防泄漏)。
cat > $D/_rr.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
outbounds:
  - name: direct
    type: direct
  - name: block
    type: block
dns:
  enabled: true
  detour: direct
  nameservers:
    - tag: d
      address: udp://127.0.0.11:53
      detour: direct
routing:
  default: direct
  rules:
    - ip-cidr:
        - $BLOCKIP/32
      to: block
Y
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_rr.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 2
probe(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 -x socks5h://${PFX}s:1080 "$1" 2>&1; }
pass=0; fail=0
chk(){ # $1 label  $2 url  $3 want(ok|blocked)
  local out; out=$(probe "$2")
  local got=blocked; echo "$out" | grep -q Hostname && got=ok
  if [ "$got" = "$3" ]; then echo "  [$1] PASS ($got)"; pass=$((pass+1)); else echo "  [$1] FAIL (want $3 got $got): $(echo "$out"|head -c80)"; fail=$((fail+1)); fi
}
# ① 崩点1 核心:socks5h 打【域名】block(只有 ip-cidr 规则)→ 解析出 IP 命中 cidr → block(修复前会 ok=漏)
chk "域名目标解析→命中 ip-cidr→block" "http://${PFX}block/" blocked
# ② 控制组:域名 allow 解析出的 IP 不在 cidr → default direct → 200(证不误伤域名/default,且直连拨号用域名可达)
chk "域名目标解析→不在 cidr→direct"    "http://${PFX}allow/" ok
# ③ 纯 IP 目标路径不变
chk "纯 IP 目标→命中 ip-cidr→block"     "http://$BLOCKIP/"    blocked
echo "═══ 崩点1 resolve-for-routing e2e: $pass 通 / $fail 失败 ═══"
cleanup; echo DONE
