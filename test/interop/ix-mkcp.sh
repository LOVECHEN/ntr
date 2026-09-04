#!/bin/bash
# mKCP(可靠-UDP)交叉验证:NTR mkcp 传输 <-> {xray, mihomo}。header=none(经典 mkcp)。
# mkcp 是 UDP-base:NTR 出站 DialBase(UDP+KCP)、入站 ListenBase(UDP 监听 + KCP accept)。
# ★ xray 26.3.27 把 mkcp header/seed 移入 finalmask:经典帧 = udp mask [mkcp-original](实测与 NTR/mihomo 经典互通)。
# ★ mihomo mkcp 挂在 vmess(非 vless):client network=kcp+mkcp-opts、listener mkcp-config.enable。
# 故 xray 侧用 vless base、mihomo 侧用 vmess base;NTR 两者皆可。sing-box 无 mkcp,不在范围。
set -u
NET=ix-mk; PFX=ixmkt-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; UUID="11111111-1111-1111-1111-111111111111"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

# --- NTR(vless base,配 xray)---
ntrv_srv(){ cat > "$1" <<Y
inbounds:
  - name: srv-in
    type: vless
    listen: 0.0.0.0:10000
    mkcp:
      header: none
    users:
      - uuid: "$UUID"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
}
ntrv_cli(){ cat > "$1" <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: vless
    server: "${PFX}s:10000"
    secret: "$UUID"
    mkcp:
      header: none
Y
}
# --- NTR(vmess base,配 mihomo)---
ntrm_srv(){ cat > "$1" <<Y
inbounds:
  - name: srv-in
    type: vmess
    listen: 0.0.0.0:10000
    uuid: "$UUID"
    mkcp:
      header: none
    users:
      - uuid: "$UUID"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
}
ntrm_cli(){ cat > "$1" <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: vmess
    server: "${PFX}s:10000"
    secret: "$UUID"
    uuid: "$UUID"
    mkcp:
      header: none
Y
}
# --- xray(vless + 新 mkcp:finalmask udp mkcp-original)---
xray_srv(){ cat > "$1" <<J
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"vless","settings":{"clients":[{"id":"$UUID"}],"decryption":"none"},"streamSettings":{"network":"kcp","kcpSettings":{},"finalmask":{"udp":[{"type":"mkcp-original"}]}}}],"outbounds":[{"protocol":"freedom"}]}
J
}
xray_cli(){ cat > "$1" <<J
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"${PFX}s","port":10000,"users":[{"id":"$UUID","encryption":"none"}]}]},"streamSettings":{"network":"kcp","kcpSettings":{},"finalmask":{"udp":[{"type":"mkcp-original"}]}}}]}
J
}
# --- mihomo(vmess + mkcp)---
mihomo_srv(){ cat > "$1" <<Y
log-level: warning
listeners:
  - {name: vmess-in, type: vmess, listen: 0.0.0.0, port: 10000, users: [{username: u, uuid: $UUID, alterId: 0}], mkcp-config: {enable: true, header: none}}
Y
}
mihomo_cli(){ cat > "$1" <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - {name: o, type: vmess, server: ${PFX}s, port: 10000, uuid: $UUID, alterId: 0, cipher: auto, network: kcp, mkcp-opts: {header: none}}
rules: ["MATCH,o"]
Y
}
run(){ local role=$1 eng=$2 f=$3 name=$4; docker rm -f $name >/dev/null 2>&1
  case $eng in
    ntr)    docker run -d --name $name --network $NET -v $NTR:/ntr:ro -v $f:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    xray)   docker run -d --name $name --network $NET -v $f:/c.json:ro ghcr.io/xtls/xray-core:latest run -c /c.json >/dev/null 2>&1;;
    mihomo) docker run -d --name $name --network $NET -v $f:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
  esac; }
runtcp(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null; }

# $1 label $2 srv-gen $3 srv-eng $4 cli-gen $5 cli-eng
test_case(){
  local sn=${PFX}s cn=${PFX}c scfg=$D/_mkt_s_$1 ccfg=$D/_mkt_c_$1
  docker rm -f $sn $cn >/dev/null 2>&1
  $2 "$scfg"; run srv $3 "$scfg" $sn; sleep 2
  $4 "$ccfg"; run cli $5 "$ccfg" $cn; sleep 2
  local ok=FAIL i; for i in 1 2 3 4 5; do echo "$(runtcp)" | grep -q Hostname && { ok=PASS; break; }; sleep 1; done
  echo "  [$1]  $ok"
  [ $ok = FAIL ] && { docker logs $cn 2>&1|tail -2|sed 's/^/    CLI:/'; docker logs $sn 2>&1|tail -2|sed 's/^/    SRV:/'; }
  docker rm -f $sn $cn >/dev/null 2>&1
}

test_case "NTR<-NTR"        ntrv_srv ntr    ntrv_cli ntr
test_case "xray<-NTR"       xray_srv xray   ntrv_cli ntr
test_case "NTR<-xray"       ntrv_srv ntr    xray_cli xray
test_case "mihomo<-NTR"     mihomo_srv mihomo ntrm_cli ntr
test_case "NTR<-mihomo"     ntrm_srv ntr    mihomo_cli mihomo
cleanup; echo DONE
