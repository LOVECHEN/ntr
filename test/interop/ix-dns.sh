#!/bin/bash
# 内置 dns 出站验证(承设计 §10.1 消费者②):DNS 报文交 route.Resolver.Exchange 解析 → 上游(经 detour)。
# 用 tunnel(udp+tcp) 入站把 :5300 的 DNS 流量导到 dns 出站(target 被 dns 出站忽略)。
#   dig @NTR -p 5300 <域名> → dns 出站 → 上游(1.1.1.1/8.8.8.8,detour=direct)→ 应答。UDP + TCP。
#   正确性:NTR 解出的 A 记录与直查上游一致(域名可解析)。
set -u
NET=ix-dns; PFX=ixdns-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1

cat > $D/_dns.yaml <<Y
dns:
  enabled: true
  strategy: race
  nameservers:
    - {tag: cf,     address: "udp://1.1.1.1:53", detour: direct}
    - {tag: google, address: "udp://8.8.8.8:53", detour: direct}
inbounds:
  - {listen: 0.0.0.0:5300, type: tunnel, target: "1.1.1.1:53", network: [udp, tcp], outbound: dnsout}
outbounds:
  - {name: dnsout, type: dns}
  - {name: direct, type: direct}
Y
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_dns.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
S=$(docker inspect ${PFX}s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
sleep 2
echo "NTR dns 服务 S=$S"

dig(){ docker run --rm --network $NET alpine sh -c "apk add -q bind-tools >/dev/null 2>&1; $1" 2>/dev/null; }

echo "=== UDP:dig @NTR -p 5300 example.com ==="
r=$(dig "dig +short +time=6 @$S -p 5300 example.com A")
echo "  应答: $(echo $r | tr '\n' ' ')"
u=FAIL; echo "$r" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' && u=PASS
echo "  [dns 出站 UDP 解析 example.com]  $u"

echo "=== TCP:dig +tcp @NTR -p 5300 cloudflare.com ==="
r=$(dig "dig +short +tcp +time=6 @$S -p 5300 cloudflare.com A")
echo "  应答: $(echo $r | tr '\n' ' ')"
t=FAIL; echo "$r" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' && t=PASS
echo "  [dns 出站 TCP 解析 cloudflare.com]  $t"

echo "=== 对照:直查 1.1.1.1 example.com(应一致可解析)==="
d=$(dig "dig +short +time=6 @1.1.1.1 example.com A")
echo "  直查: $(echo $d | tr '\n' ' ')"

[ $u = FAIL -o $t = FAIL ] && docker logs ${PFX}s 2>&1 | tail -5 | sed 's/^/  NTR:/'
cleanup; echo DONE