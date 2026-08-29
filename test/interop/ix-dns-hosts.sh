#!/bin/bash
# hosts 静态映射验证:配 hosts:{pinned.test:[9.9.9.9]} + 真上游。dig pinned.test 必回 9.9.9.9(命中 hosts、不走上游);
# dig example.com 走上游得真 IP(证 hosts 不破正常解析)。
set -u
NET=ix-hosts; PFX=ixhosts-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
cat > $D/_hosts.yaml <<'Y'
dns:
  enabled: true
  strategy: sequential
  hosts:
    pinned.test: ["9.9.9.9"]
  nameservers:
    - {tag: cf, address: "udp://1.1.1.1:53", detour: direct}
inbounds:
  - {listen: 0.0.0.0:5300, type: tunnel, target: "1.1.1.1:53", network: [udp], outbound: dnsout}
outbounds:
  - {name: dnsout, type: dns}
  - {name: direct, type: direct}
Y
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_hosts.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
S=$(docker inspect ${PFX}s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
sleep 2
dig1(){ docker run --rm --network $NET alpine sh -c "apk add -q bind-tools >/dev/null 2>&1; dig +short +time=10 @$S -p 5300 $1 A" 2>/dev/null; }
echo "=== hosts 命中 pinned.test → 必 9.9.9.9 ==="
r1=$(dig1 pinned.test); echo "  pinned.test → $(echo $r1|tr '\n' ' ')"
ok1=FAIL; [ "$(echo "$r1"|head -1)" = "9.9.9.9" ] && ok1=PASS
echo "  [hosts 命中不走上游]  $ok1"
echo "=== 正常域名 example.com → 走上游得真 IP ==="
r2=$(dig1 example.com); echo "  example.com → $(echo $r2|tr '\n' ' ')"
ok2=FAIL; echo "$r2" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' && ok2=PASS
echo "  [hosts 不破正常解析]  $ok2"
[ $ok1 = FAIL -o $ok2 = FAIL ] && docker logs ${PFX}s 2>&1 | tail -6 | sed 's/^/  NTR:/'
cleanup; echo DONE
