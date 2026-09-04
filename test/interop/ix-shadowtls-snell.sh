#!/bin/bash
# 组5 互通回归:ShadowTLS(v2/v3)+ Snell(v4/v5)
# 对端:sing-box(shadowtls v1/2/3)、mihomo(shadowtls 作 SS plugin;snell v1-5)
# 专属:network=ix-sn 容器前缀=ixn-
set -u
NET=ix-sn; D=/tmp/ntr-interop; DEST=www.apple.com
NTR=$D/ntr
MI=metacubex/mihomo:latest
SB=ghcr.io/sagernet/sing-box:latest
CURL=curlimages/curl:latest

docker network create $NET >/dev/null 2>&1
docker rm -f ixn-target >/dev/null 2>&1
docker run -d --name ixn-target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

pass=0; fail=0; RESULTS=""
cleanup_pair(){ docker rm -f ixn-srv ixn-cli >/dev/null 2>&1; }
# CHK <proxy-container> : socks5h 经代理打靶机
CHK(){ for i in 1 2 3 4 5; do
  docker run --rm --network $NET $CURL -s --max-time 8 -x socks5h://$1:1080 http://ixn-target/ 2>/dev/null | grep -q Hostname && return 0
  sleep 1.5; done; return 1; }
REC(){ # REC <label> <rc>
  if [ "$2" = 0 ]; then echo "  ✅ $1"; pass=$((pass+1)); RESULTS="$RESULTS\n✅ $1";
  else echo "  ❌ $1"; fail=$((fail+1)); RESULTS="$RESULTS\n❌ $1";
    echo "    -- srv logs --"; docker logs ixn-srv 2>&1 | tail -4 | sed 's/^/    /';
    echo "    -- cli logs --"; docker logs ixn-cli 2>&1 | tail -4 | sed 's/^/    /'; fi; }

run_ntr_srv(){ docker run -d --name ixn-srv --network $NET -e NTR_DEBUG=1 -v $NTR:/ntr:ro -v $1:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_ntr_cli(){ docker run -d --name ixn-cli --network $NET -e NTR_DEBUG=1 -v $NTR:/ntr:ro -v $1:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_mi(){ docker run -d --name $1 --network $NET -v $2:/root/.config/mihomo/config.yaml:ro $MI >/dev/null 2>&1; }
run_sb(){ docker run -d --name $1 --network $NET -v $2:/etc/sing-box/config.json:ro $SB run -c /etc/sing-box/config.json >/dev/null 2>&1; }

echo "======== ShadowTLS + ShadowSocks ========"
for VER in 3 2; do
  ############ NTR-server ← mihomo-client ############
  cleanup_pair
  cat > $D/ix-st-srv.yaml <<EOF
inbounds:
  - name: st-in
    type: shadowsocks
    listen: 0.0.0.0:10000
    method: aes-256-gcm
    password: sspw
    shadowtls:
      version: $VER
      password: stpw
      sni: $DEST
      handshake: $DEST:443
    outbound: direct
outbounds:
  - name: direct
    type: direct
EOF
  run_ntr_srv $D/ix-st-srv.yaml
  cat > $D/ix-st-mc.yaml <<EOF
mixed-port: 1080
allow-lan: true
bind-address: "*"
log-level: warning
proxies:
  - {name: p, type: ss, server: ixn-srv, port: 10000, cipher: aes-256-gcm, password: sspw, plugin: shadow-tls, plugin-opts: {host: "$DEST", password: stpw, version: $VER}}
rules: ["MATCH,p"]
EOF
  run_mi ixn-cli $D/ix-st-mc.yaml
  sleep 4; CHK ixn-cli; REC "shadowtls v$VER + ss | 对端→NTR | mihomo v1.19.30(SS+shadow-tls plugin) → NTR服务端" $?

  ############ NTR-server ← sing-box-client ############
  cleanup_pair
  run_ntr_srv $D/ix-st-srv.yaml
  cat > $D/ix-sb-cli.json <<EOF
{ "log": {"level":"warn"},
  "inbounds": [{"type":"socks","tag":"socks-in","listen":"0.0.0.0","listen_port":1080}],
  "outbounds": [
    {"type":"shadowsocks","tag":"ss-out","method":"aes-256-gcm","password":"sspw","detour":"stls-out"},
    {"type":"shadowtls","tag":"stls-out","server":"ixn-srv","server_port":10000,"version":$VER,"password":"stpw",
     "tls":{"enabled":true,"server_name":"$DEST","insecure":true}}
  ], "route": {"final":"ss-out"} }
EOF
  run_sb ixn-cli $D/ix-sb-cli.json
  sleep 4; CHK ixn-cli; REC "shadowtls v$VER + ss | 对端→NTR | sing-box 1.13.19 → NTR服务端" $?

  ############ NTR-client → sing-box-server ############
  cleanup_pair
  cat > $D/ix-sb-srv.json <<EOF
{ "log": {"level":"warn"},
  "inbounds": [
    {"type":"shadowtls","tag":"stls-in","listen":"0.0.0.0","listen_port":10000,"version":$VER,
     $( [ $VER = 3 ] && echo '"users":[{"name":"u","password":"stpw"}],' || echo '"password":"stpw",' )
     "handshake":{"server":"$DEST","server_port":443},"detour":"ss-in"},
    {"type":"shadowsocks","tag":"ss-in","method":"aes-256-gcm","password":"sspw"}
  ], "outbounds": [{"type":"direct","tag":"direct"}] }
EOF
  run_sb ixn-srv $D/ix-sb-srv.json
  cat > $D/ix-ntr-cli.yaml <<EOF
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: shadowsocks
    server: "ixn-srv:10000"
    method: aes-256-gcm
    password: sspw
    shadowtls:
      version: $VER
      password: stpw
      sni: $DEST
      handshake: $DEST:443
      insecure: true
EOF
  run_ntr_cli $D/ix-ntr-cli.yaml
  sleep 4; CHK ixn-cli; REC "shadowtls v$VER + ss | NTR→对端 | NTR客户端 → sing-box 1.13.19 服务端" $?
done

echo "======== Snell (mihomo v1.19.30) ========"
for VER in 4 5; do
  ############ NTR-server ← mihomo-client ############
  cleanup_pair
  cat > $D/ix-sn-srv.yaml <<EOF
inbounds:
  - name: snell-in
    type: snell
    listen: 0.0.0.0:10000
    psk: snellpsk0123456789abcdef
    version: $VER
    outbound: direct
outbounds:
  - name: direct
    type: direct
EOF
  run_ntr_srv $D/ix-sn-srv.yaml
  cat > $D/ix-sn-mc.yaml <<EOF
mixed-port: 1080
allow-lan: true
bind-address: "*"
log-level: warning
mode: rule
proxies:
  - {name: p, type: snell, server: ixn-srv, port: 10000, psk: "snellpsk0123456789abcdef", version: $VER, udp: true}
rules: ["MATCH,p"]
EOF
  run_mi ixn-cli $D/ix-sn-mc.yaml
  sleep 4; CHK ixn-cli; REC "snell v$VER | 对端→NTR | mihomo v1.19.30 → NTR服务端" $?

  ############ NTR-client → mihomo-server ############
  cleanup_pair
  cat > $D/ix-sn-msrv.yaml <<EOF
mixed-port: 7890
allow-lan: true
bind-address: "*"
log-level: warning
listeners:
  - name: snell-in
    type: snell
    listen: 0.0.0.0
    port: 10000
    psk: "snellpsk0123456789abcdef"
    version: $VER
proxies: []
rules: ["MATCH,DIRECT"]
EOF
  run_mi ixn-srv $D/ix-sn-msrv.yaml
  cat > $D/ix-sn-ntrcli.yaml <<EOF
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: snell
    server: "ixn-srv:10000"
    psk: snellpsk0123456789abcdef
    version: $VER
EOF
  run_ntr_cli $D/ix-sn-ntrcli.yaml
  sleep 4; CHK ixn-cli; REC "snell v$VER | NTR→对端 | NTR客户端 → mihomo v1.19.30 服务端(listener)" $?
done

echo ""
echo "======== 汇总 ========"
echo -e "$RESULTS"
echo ""
echo "通过 $pass / 失败 $fail"

if [ "${KEEP:-0}" != 1 ]; then
  cleanup_pair; docker rm -f ixn-target >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
fi
