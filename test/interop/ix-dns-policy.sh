#!/bin/bash
# ============================================================================
# nameserver-policy 端到端(承设计 §10.1 policy):按域名选 DNS 上游。
# 两个权威上游 CoreDNS:dsA 对任何 A 查询答 10.99.0.1、dsB 答 10.99.0.2。
# NTR sequential 默认走 dsA(首选先应答);nameserver-policy:suffix policy.test → dsB。
#   dig other.example.com → 10.99.0.1(默认 dsA)  dig x.policy.test → 10.99.0.2(policy→dsB)
# 判据:同一 NTR、按查询域名解析到【不同上游】的固定 IP,证明按域名选上游生效。
# 专属 network=ix-dnspol;前缀=ixdp-
# ============================================================================
set -u
NET=ix-dnspol; PFX=ixdp-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
PASS=0; FAIL=0
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
cleanup; docker network create $NET >/dev/null 2>&1

# 两个权威上游(CoreDNS template:对任何 A 查询答固定 IP,区分是哪台上游应答的)
mkcore(){ printf '.:53 {\n  template IN A {\n    answer "{{ .Name }} 60 IN A %s"\n  }\n}\n' "$1"; }
mkcore 10.99.0.1 > $D/_corefileA
mkcore 10.99.0.2 > $D/_corefileB
docker run -d --name ${PFX}dsA --network $NET -v $D/_corefileA:/Corefile:ro coredns/coredns:latest -conf /Corefile >/dev/null 2>&1
docker run -d --name ${PFX}dsB --network $NET -v $D/_corefileB:/Corefile:ro coredns/coredns:latest -conf /Corefile >/dev/null 2>&1
sleep 2
IPA=$(docker inspect ${PFX}dsA --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
IPB=$(docker inspect ${PFX}dsB --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "上游 dsA=$IPA(答 10.99.0.1)  dsB=$IPB(答 10.99.0.2)"

cat > $D/_dnspol.yaml <<Y
dns:
  enabled: true
  strategy: sequential
  nameservers:
    - {tag: dsA, address: "udp://$IPA:53", detour: direct}
    - {tag: dsB, address: "udp://$IPB:53", detour: direct}
  nameserver-policy:
    - {domain-suffix: [policy.test], nameserver: [dsB]}
inbounds:
  - {listen: 0.0.0.0:5300, type: tunnel, target: "10.0.0.1:53", network: [udp, tcp], outbound: dnsout}
outbounds:
  - {name: dnsout, type: dns}
  - {name: direct, type: direct}
Y
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_dnspol.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
S=$(docker inspect ${PFX}s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
sleep 2
echo "NTR dns 服务 S=$S"

dig1(){ docker run --rm --network $NET alpine sh -c "apk add -q bind-tools >/dev/null 2>&1; dig +short +time=6 @$S -p 5300 $1 A" 2>/dev/null | grep -E '^[0-9]+\.' | head -1; }
check(){ local dom=$1 want=$2 desc=$3 got
  got=$(dig1 "$dom")
  if [ "$got" = "$want" ]; then echo "  ✅ $desc:$dom → $got"; PASS=$((PASS+1))
  else echo "  ❌ $desc:$dom → 得 '$got' 期望 '$want'"; FAIL=$((FAIL+1)); fi
}

echo "=== 按域名选上游 ==="
check other.example.com    10.99.0.1 "默认(sequential 首选 dsA)"
check www.policy.test      10.99.0.2 "policy 命中(后缀 policy.test → dsB)"
check policy.test          10.99.0.2 "policy 后缀==自身"
check deep.sub.policy.test 10.99.0.2 "policy 多级子域"
check notpolicy.test       10.99.0.1 "标签边界(notpolicy.test 不误命中 → 默认 dsA)"

[ $FAIL -ne 0 ] && { echo "--- NTR 日志 ---"; docker logs ${PFX}s 2>&1 | tail -8 | sed 's/^/  /'; }
echo "════════ ix-dns-policy:PASS=$PASS FAIL=$FAIL ════════"
[ $FAIL -eq 0 ] && echo "✅ nameserver-policy 全绿" || echo "❌ 有失败"
