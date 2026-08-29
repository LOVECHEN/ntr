#!/bin/bash
set -u
NET=wg-net; D=/tmp/ntr-interop
cleanup(){ docker rm -f wg-target wg-srv wg-cli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
docker network create $NET >/dev/null 2>&1; docker rm -f wg-target wg-srv wg-cli >/dev/null 2>&1
docker run -d --name wg-target --network $NET traefik/whoami >/dev/null

KEYS=$(docker run --rm alpine sh -c 'apk add -q wireguard-tools >/dev/null 2>&1; \
  sp=$(wg genkey); spub=$(echo "$sp"|wg pubkey); \
  cp=$(wg genkey); cpub=$(echo "$cp"|wg pubkey); \
  echo "$sp|$spub|$cp|$cpub"')
SPRIV=$(echo "$KEYS"|cut -d'|' -f1); SPUB=$(echo "$KEYS"|cut -d'|' -f2)
CPRIV=$(echo "$KEYS"|cut -d'|' -f3); CPUB=$(echo "$KEYS"|cut -d'|' -f4)
echo "密钥已生成(真 wg genkey)"

# 服务端脚本:用【内核 WireGuard 实现】(OrbStack 内核原生支持),最权威的对端
cat > $D/wg-srv.sh <<INNER
set -e
apk add -q wireguard-tools iptables >/dev/null 2>&1
ip link add wg0 type wireguard
ip addr add 10.7.0.1/24 dev wg0
cat > /tmp/wg0.conf <<CONF
[Interface]
PrivateKey = $SPRIV
ListenPort = 51820
[Peer]
PublicKey = $CPUB
AllowedIPs = 10.7.0.2/32
CONF
wg setconf wg0 /tmp/wg0.conf
ip link set wg0 up
iptables -t nat -A POSTROUTING -s 10.7.0.0/24 -o eth0 -j MASQUERADE
echo "WG-SERVER-READY (kernel wireguard)"
wg show
sleep 3600
INNER

docker run -d --name wg-srv --network $NET --cap-add NET_ADMIN --cap-add SYS_MODULE \
  --sysctl net.ipv4.ip_forward=1 \
  -v $D/wg-srv.sh:/s.sh:ro alpine sh /s.sh >/dev/null 2>&1
for i in $(seq 1 25); do docker logs wg-srv 2>&1 | grep -q WG-SERVER-READY && break; sleep 1; done
docker logs wg-srv 2>&1 | grep -q WG-SERVER-READY || { echo "❌ WG 服务端未就绪"; docker logs wg-srv 2>&1|tail -10; exit 1; }
echo "✅ 真 WireGuard 服务端就绪(内核实现)"

printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - name: up\n    type: wireguard\n    server: "wg-srv:51820"\n    private-key: "%s"\n    peer-public-key: "%s"\n    local-address: ["10.7.0.2/32"]\n    allowed-ips: ["0.0.0.0/0"]\n    keepalive: 15\n' "$CPRIV" "$SPUB" > $D/wg-cli.yaml
docker run -d --name wg-cli --network $NET -e NTR_DEBUG=1 -v $D/ntr-wg:/ntr:ro -v $D/wg-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 6
TIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' wg-target)
OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 15 -x socks5h://wg-cli:1080 "http://$TIP/" 2>&1)
if echo "$OUT" | grep -q Hostname; then
  echo "✅ NTR WireGuard 客户端 → 真内核 WireGuard 服务端 → 靶机  通"
  echo "--- 服务端握手状态 ---"; docker exec wg-srv wg show 2>/dev/null | grep -E "peer|handshake|transfer" | head -5
else
  echo "❌ 不通"; echo "--- ntr ---"; docker logs wg-cli 2>&1|tail -8
  echo "--- wg show ---"; docker exec wg-srv wg show 2>/dev/null|head -12
fi
