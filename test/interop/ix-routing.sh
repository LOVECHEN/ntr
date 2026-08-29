#!/bin/bash
# 规则分流引擎(§8.3)e2e:NTR socks 入站 + routing: 规则块,按目标【域名/IP/端口】选出站。
# 验证「首个命中」派发真的接进数据路径:命中 block 规则的目标被拒、未命中走 default direct 的通。
# (分流决策是 NTR 内部行为、无跨引擎线格式;此处以「direct 通 / block 拒」观测选中的出站。)
set -u
NET=ix-rt; PFX=ixrt-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}allow --network $NET traefik/whoami >/dev/null 2>&1
docker run -d --name ${PFX}block --network $NET traefik/whoami >/dev/null 2>&1
sleep 1
BLOCKIP=$(docker inspect ${PFX}block --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
cat > $D/_rt.yaml <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}]}
outbounds:
  - {name: direct, type: direct}
  - {name: block, type: block}
routing:
  default: direct
  rules:
    - domain: [${PFX}block]
      to: block
    - ip-cidr: [$BLOCKIP/32]
      to: block
Y
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_rt.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 2
probe(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 -x socks5h://${PFX}s:1080 "$1" 2>&1; }
pass=0; fail=0
chk(){ # $1 label  $2 url  $3 want(ok|blocked)
  local out; out=$(probe "$2")
  local got=blocked; echo "$out" | grep -q Hostname && got=ok
  if [ "$got" = "$3" ]; then echo "  [$1] PASS ($got)"; pass=$((pass+1)); else echo "  [$1] FAIL (want $3 got $got): $(echo "$out"|head -c60)"; fail=$((fail+1)); fi
}
chk "default direct: allow 域名"      "http://${PFX}allow/"    ok
chk "domain 规则 → block: block 域名"  "http://${PFX}block/"    blocked
chk "ip-cidr 规则 → block: block IP"   "http://$BLOCKIP/"       blocked
echo "═══ 分流 e2e: $pass 通 / $fail 失败 ═══"
cleanup; echo DONE
