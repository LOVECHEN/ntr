#!/bin/bash
# DoH3(DNS-over-HTTP/3,RFC 8484 的 DoH wire 跑在 HTTP/3 上)上游验证:内置 dns 出站经 DoH3 上游解析。
# 上游用真 Cloudflare(h3://1.1.1.1/dns-query,证书 cloudflare-dns.com,支持 HTTP/3)。tunnel(udp) 入站导流到 dns 出站。
set -u
NET=ix-doh3; PFX=ixdoh3-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
cat > $D/_doh3.yaml <<'Y'
dns:
  enabled: true
  strategy: sequential
  nameservers:
    - tag: cf-doh3
      address: "h3://1.1.1.1/dns-query"
      sni: "cloudflare-dns.com"
      detour: direct
inbounds:
  - {listen: 0.0.0.0:5300, type: tunnel, target: "1.1.1.1:53", network: [udp], outbound: dnsout}
outbounds:
  - {name: dnsout, type: dns}
  - {name: direct, type: direct}
Y
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_doh3.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
S=$(docker inspect ${PFX}s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
sleep 2
echo "=== dig @NTR:5300(经 DoH3 上游)example.com ==="
r=$(docker run --rm --network $NET alpine sh -c "apk add -q bind-tools >/dev/null 2>&1; dig +short +time=10 @$S -p 5300 example.com A" 2>/dev/null)
echo "  应答: $(echo $r | tr '\n' ' ')"
ok=FAIL; echo "$r" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' && ok=PASS
echo "  [dns 出站 ← DoH3(h3://Cloudflare/dns-query)]  $ok"
[ $ok = FAIL ] && docker logs ${PFX}s 2>&1 | tail -6 | sed 's/^/  NTR:/'
cleanup; echo DONE
