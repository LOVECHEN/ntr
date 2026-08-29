#!/bin/bash
# 加密 DNS 上游验证(承设计 §10.1.3):内置 dns 出站经 DoT / DoH 上游(经 detour)解析。
# 用 tunnel(udp) 入站把 :5300 的 DNS 导到 dns 出站。上游用真 Cloudflare(1.1.1.1,证书含 IP SAN)。
#   A. DoT   tls://1.1.1.1:853
#   B. DoH   https://1.1.1.1/dns-query
# 正确性:经加密上游解出的 A 记录可用(与明文一致)。
set -u
NET=ix-edns; PFX=ixedns-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
dig(){ docker run --rm --network $NET alpine sh -c "apk add -q bind-tools >/dev/null 2>&1; $1" 2>/dev/null; }

run_case(){ # $1 label  $2 address  $3 domain  $4 tag(唯一,作配置文件名)
  docker rm -f ${PFX}s >/dev/null 2>&1
  # ★每 case 一份唯一配置文件 + 地址直接内插(不用 sed):macOS `sed -i ''` 走原子 rename 换 inode,
  #   重写【被单文件 bind-mount 的】配置时 OrbStack 会让容器读到截断视图 → YAML 解析炸(伪 FAIL)。
  #   故不复用同名文件、不原地改被挂载文件;每份写一次、永不再动。
  local cfg=$D/_edns_$4.yaml
  cat > "$cfg" <<Y
dns:
  enabled: true
  strategy: sequential
  nameservers:
    - tag: ns
      address: "$2"
      detour: direct
inbounds:
  - {listen: 0.0.0.0:5300, type: tunnel, target: "1.1.1.1:53", network: [udp], outbound: dnsout}
outbounds:
  - {name: dnsout, type: dns}
  - {name: direct, type: direct}
Y
  docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v "$cfg":/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  local S; S=$(docker inspect ${PFX}s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
  sleep 2
  local r ok=FAIL
  r=$(dig "dig +short +time=8 @$S -p 5300 $3 A")
  echo "$r" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' && ok=PASS
  echo "  [$1]  $ok   应答:$(echo $r | tr '\n' ' ' | cut -c1-60)"
  [ $ok = FAIL ] && docker logs ${PFX}s 2>&1 | tail -4 | sed 's/^/    NTR:/'
}

run_case "A. dns 出站 ← DoT(tls://1.1.1.1:853)"        "tls://1.1.1.1:853"        example.com    dot
run_case "B. dns 出站 ← DoH(https://1.1.1.1/dns-query)" "https://1.1.1.1/dns-query" cloudflare.com doh
rm -f $D/_edns_dot.yaml $D/_edns_doh.yaml
cleanup; echo DONE