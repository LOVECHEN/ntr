#!/bin/bash
# 组9: 反向代理 bridge/portal 互通回归 (NTR ⇄ xray-core reverse 形态A)
# 专属隔离: network=ix-rv, 容器前缀=ixw-
set -u
NET=ix-rv; D=/tmp/ntr-interop; U=11111111-1111-1111-1111-111111111111; CD=reverse.ntr
XRAY=ghcr.io/xtls/xray-core:latest
PASS=0; FAIL=0

cleanup(){ docker rm -f ixw-target ixw-echo ixw-xportal ixw-nportal ixw-xbridge ixw-bridge ixw-usr ixw-cli >/dev/null 2>&1; }
trap cleanup EXIT
docker network create $NET >/dev/null 2>&1

xray_ver(){ docker run --rm $XRAY version 2>/dev/null | head -1; }
echo "### xray 版本: $(xray_ver)"
echo

# ---------------------------------------------------------------------------
# 用例1: NTR bridge ⇄ xray portal (形态A). 用户 → NTR client → xray vless 入站
#        → xray portal 反连复用 → NTR bridge 落地 target. target 来源应==bridge
# ---------------------------------------------------------------------------
case1(){
  echo "===== 用例1: NTR bridge  ⇄  xray portal  (方向: NTR→对端 portal 由 xray) ====="
  cleanup
  docker run -d --name ixw-target --network $NET traefik/whoami >/dev/null
  cat > $D/ixr-xportal.json <<EOF
{ "log": {"loglevel": "warning"},
  "reverse": {"portals": [{"tag": "portal", "domain": "$CD"}]},
  "inbounds": [{"tag": "vin", "listen": "0.0.0.0", "port": 10000, "protocol": "vless",
    "settings": {"clients": [{"id": "$U"}], "decryption": "none"}}],
  "routing": {"rules": [{"inboundTag": ["vin"], "outboundTag": "portal"}]},
  "outbounds": [{"protocol": "freedom", "tag": "direct"}] }
EOF
  docker run -d --name ixw-xportal --network $NET -v $D/ixr-xportal.json:/cfg.json:ro $XRAY run -c /cfg.json >/dev/null 2>&1
  printf 'outbounds:\n  - {name: up, type: proxy, server: "ixw-xportal:10000", secret: "%s", layers: [{type: vless}]}\nbridges:\n  - {portal: up, control-domain: %s, pool: 2}\n' "$U" "$CD" > $D/ixr-bridge.yaml
  docker run -d --name ixw-bridge --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ixr-bridge.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: proxy, server: "ixw-xportal:10000", secret: "%s", layers: [{type: vless}]}\n' "$U" > $D/ixr-user.yaml
  docker run -d --name ixw-usr --network $NET -v $D/ntr:/ntr:ro -v $D/ixr-user.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 6
  local BIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ixw-bridge)
  local XIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ixw-xportal)
  local OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x socks5h://ixw-usr:1080 http://ixw-target/ 2>&1)
  local RA=$(echo "$OUT" | grep -i "RemoteAddr" | sed 's/RemoteAddr: //; s/:[0-9]*$//')
  echo "bridge=$BIP xportal=$XIP  target来源=$RA"
  if [ "$RA" = "$BIP" ]; then echo "✅ 用例1 通: NTR bridge ⇄ xray portal 反连,流量经隧道从 NTR bridge 落地"; PASS=$((PASS+1));
  elif [ "$RA" = "$XIP" ]; then echo "⚠ 用例1: 来源==xportal, xray 直连了 target(反连未走 NTR bridge)"; FAIL=$((FAIL+1));
    echo "xportal:"; docker logs ixw-xportal 2>&1|tail -6; echo "bridge:"; docker logs ixw-bridge 2>&1|tail -6;
  else echo "❌ 用例1 不通: 来源=$RA OUT=$OUT"; FAIL=$((FAIL+1));
    echo "xportal:"; docker logs ixw-xportal 2>&1|tail -8; echo "bridge:"; docker logs ixw-bridge 2>&1|tail -8; fi
  echo
}

# ---------------------------------------------------------------------------
# 用例2: xray bridge ⇄ NTR portal. 用户 → NTR client → NTR portal(vless入站)
#        → NTR portal 反连复用 → xray bridge 落地 target. target 来源应==xbridge
# ---------------------------------------------------------------------------
case2(){
  echo "===== 用例2: xray bridge  ⇄  NTR portal  (方向: 对端 bridge 由 xray → NTR) ====="
  cleanup
  docker run -d --name ixw-target --network $NET traefik/whoami >/dev/null
  printf 'inbounds:\n  - listen: 0.0.0.0:10000\n    type: portal\n    control-domain: %s\n    layers: [{type: vless}]\n    users: [{uuid: %s}]\noutbounds: [{name: direct, type: direct}]\n' "$CD" "$U" > $D/ixr-nportal.yaml
  docker run -d --name ixw-nportal --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ixr-nportal.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  cat > $D/ixr-xbridge.json <<EOF
{ "log": {"loglevel": "warning"},
  "reverse": {"bridges": [{"tag": "bridge", "domain": "$CD"}]},
  "outbounds": [
    {"tag": "tunnel", "protocol": "vless", "settings": {"vnext": [{"address": "ixw-nportal", "port": 10000, "users": [{"id": "$U", "encryption": "none"}]}]}},
    {"tag": "out-direct", "protocol": "freedom"} ],
  "routing": {"rules": [
    {"inboundTag": ["bridge"], "domain": ["full:$CD"], "outboundTag": "tunnel"},
    {"inboundTag": ["bridge"], "outboundTag": "out-direct"} ]} }
EOF
  docker run -d --name ixw-xbridge --network $NET -v $D/ixr-xbridge.json:/cfg.json:ro $XRAY run -c /cfg.json >/dev/null 2>&1
  printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: proxy, server: "ixw-nportal:10000", secret: "%s", layers: [{type: vless}]}\n' "$U" > $D/ixr-user2.yaml
  docker run -d --name ixw-usr --network $NET -v $D/ntr:/ntr:ro -v $D/ixr-user2.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 6
  local XBIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ixw-xbridge)
  local NIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ixw-nportal)
  echo "portal 隧道注册:"; docker logs ixw-nportal 2>&1 | tail -3
  local OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x socks5h://ixw-usr:1080 http://ixw-target/ 2>&1)
  local RA=$(echo "$OUT" | grep -i "RemoteAddr" | sed 's/RemoteAddr: //; s/:[0-9]*$//')
  echo "xbridge=$XBIP nportal=$NIP  target来源=$RA"
  if [ "$RA" = "$XBIP" ]; then echo "✅ 用例2 通: xray bridge ⇄ NTR portal 反连(NTR ServerWorker 对真 xray ClientWorker/心跳)"; PASS=$((PASS+1));
  elif [ "$RA" = "$NIP" ]; then echo "⚠ 用例2: 来源==nportal, 反连未走 xray bridge"; FAIL=$((FAIL+1));
    echo "nportal:"; docker logs ixw-nportal 2>&1|tail -6; echo "xbridge:"; docker logs ixw-xbridge 2>&1|tail -6;
  else echo "❌ 用例2 不通: 来源=$RA OUT=$OUT"; FAIL=$((FAIL+1));
    echo "nportal:"; docker logs ixw-nportal 2>&1|tail -8; echo "xbridge:"; docker logs ixw-xbridge 2>&1|tail -8; fi
  echo
}

# ---------------------------------------------------------------------------
# 用例3: 反连 UDP. NTR bridge ⇄ xray portal, 用户经 socks-udp 打 UDP echo
# ---------------------------------------------------------------------------
case3(){
  echo "===== 用例3: 反连 UDP  NTR bridge ⇄ xray portal (muxcool UDP 子流) ====="
  cleanup
  docker run -d --name ixw-echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
  cat > $D/ixr-xportal-u.json <<EOF
{ "log": {"loglevel": "warning"},
  "reverse": {"portals": [{"tag": "portal", "domain": "$CD"}]},
  "inbounds": [{"tag": "vin", "listen": "0.0.0.0", "port": 10000, "protocol": "vless",
    "settings": {"clients": [{"id": "$U"}], "decryption": "none"}}],
  "routing": {"rules": [{"inboundTag": ["vin"], "outboundTag": "portal"}]},
  "outbounds": [{"protocol": "freedom", "tag": "direct"}] }
EOF
  docker run -d --name ixw-xportal --network $NET -v $D/ixr-xportal-u.json:/cfg.json:ro $XRAY run -c /cfg.json >/dev/null 2>&1
  printf 'outbounds:\n  - {name: up, type: proxy, server: "ixw-xportal:10000", secret: "%s", layers: [{type: vless}]}\nbridges:\n  - {portal: up, control-domain: %s, pool: 2}\n' "$U" "$CD" > $D/ixr-bridge-u.yaml
  docker run -d --name ixw-bridge --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ixr-bridge-u.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  # socksudp.py 硬编码容器名 cli 与 echo
  printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: proxy, server: "ixw-xportal:10000", secret: "%s", layers: [{type: vless}]}\n' "$U" > $D/ixr-user-u.yaml
  docker run -d --name cli --network $NET -v $D/ntr:/ntr:ro -v $D/ixr-user-u.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  docker rm -f echo >/dev/null 2>&1
  docker run -d --name echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
  sleep 6
  local OUT=$(docker run --rm --network $NET -v $D/socksudp.py:/c.py:ro python:3-alpine python /c.py 2>&1); local RC=$?
  echo "socksudp exit=$RC; out=$OUT"
  if [ $RC -eq 0 ]; then echo "✅ 用例3 通: NTR bridge 反连 UDP ⇄ 真 xray portal 互通"; PASS=$((PASS+1));
  else echo "❌ 用例3 不通"; echo "xportal:"; docker logs ixw-xportal 2>&1|tail -6; echo "bridge:"; docker logs ixw-bridge 2>&1|tail -8; FAIL=$((FAIL+1)); fi
  docker rm -f cli echo >/dev/null 2>&1
  echo
}

case1
case2
case3
echo "===================================================="
echo "===== 组9 结果: $PASS 通 / $FAIL 失败 ====="
cleanup; docker network rm $NET >/dev/null 2>&1
