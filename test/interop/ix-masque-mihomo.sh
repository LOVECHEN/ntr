#!/bin/bash
# ============================================================================
# MASQUE 对 mihomo 单通:mihomo 的 masque 出站是 Cloudflare WARP 的 CONNECT-IP(RFC 9484,
# :protocol=cf-connect-ip,L3 IP 隧道)。NTR 的 connect-ip 服务端接受 connect-ip / cf-connect-ip
# 两种 :protocol → 能接 mihomo masque client。此前 xcheck-masque 误把 mihomo(connect-ip)对到
# NTR 的 masque(connect-udp)服务端才得 400 —— 用错服务端,非线格式不兼容。
# 方向:mihomo masque(cf-connect-ip)client → NTR connect-ip server → netstack forwarder → 落地。
# 需 -tags with_connectip 的 ntr-l3;专属 network=ix-mqmh;前缀=ixmm-
# ============================================================================
set -u
NET=ix-mqmh; PFX=ixmm-; D=/tmp/ntr-interop; NTR=${NTRL3_BIN:-$D/ntr-l3}
MI=metacubex/mihomo:latest
PASS=0; FAIL=0
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1

# NTR connect-ip server(接受 cf-connect-ip);assign-address 匹配 mihomo 期望的隧道内地址
printf 'inbounds:\n  - listen: 0.0.0.0:8443\n    type: connect-ip\n    tls: {cert-file: /cert.pem, key-file: /key.pem}\n    assign-address: "172.16.0.2/32"\noutbounds: [{name: direct, type: direct}]\n' > $D/${PFX}srv.yaml
docker run -d --name ${PFX}srv --network $NET -e NTR_DEBUG=1 -v $NTR:/ntr:ro -v $D/${PFX}srv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 3

# mihomo masque(WARP cf-connect-ip)client:EC 密钥对 + ip CIDR + endpoint 指向 NTR server
openssl ecparam -name prime256v1 -genkey -noout -out $D/${PFX}ec.key 2>/dev/null
PRIV=$(openssl ec -in $D/${PFX}ec.key -outform DER 2>/dev/null | base64 | tr -d '\n')
PUB=$(openssl ec -in $D/${PFX}ec.key -pubout -outform DER 2>/dev/null | base64 | tr -d '\n')
cat > $D/${PFX}mihomo.yaml <<EOF
mixed-port: 1080
allow-lan: true
bind-address: '*'
log-level: warning
proxies:
  - {name: up, type: masque, server: ${PFX}srv, port: 8443, sni: example.com, private-key: $PRIV, public-key: $PUB, ip: 172.16.0.2/32, mtu: 1280, skip-cert-verify: true, udp: true}
rules:
  - MATCH,up
EOF
docker run -d --name ${PFX}mihomo --network $NET -v $D/${PFX}mihomo.yaml:/root/.config/mihomo/config.yaml:ro $MI >/dev/null 2>&1
sleep 6

echo "=== mihomo masque(cf-connect-ip)client → NTR connect-ip server ==="
OUT=""; for i in 1 2 3 4 5; do OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://${PFX}mihomo:1080 http://${PFX}target/ 2>&1); echo "$OUT"|grep -q Hostname && break; sleep 2; done
if echo "$OUT"|grep -q Hostname; then
  echo "  ✅ MASQUE 对 mihomo 单通:mihomo masque(WARP cf-connect-ip)→ NTR connect-ip server → 落地"; PASS=$((PASS+1))
else echo "  ❌ 不通 OUT=$(echo "$OUT"|head -1)"; FAIL=$((FAIL+1))
  echo "  --- NTR connect-ip server ---"; docker logs ${PFX}srv 2>&1|tail -10|sed 's/^/    /'
  echo "  --- mihomo ---"; docker logs ${PFX}mihomo 2>&1|tail -10|sed 's/^/    /'
fi
echo "════════ ix-masque-mihomo:PASS=$PASS FAIL=$FAIL ════════"
[ $FAIL -eq 0 ] && echo "✅ MASQUE 对 mihomo 单通全绿" || echo "❌ 有失败"
