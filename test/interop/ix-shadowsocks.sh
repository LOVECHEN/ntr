#!/bin/bash
# 组3 Shadowsocks 双向互通回归:NTR <-> xray / mihomo / sing-box
# 覆盖:SS-2022(blake3-aes-128/256-gcm)、经典 AEAD(aes-256-gcm / chacha20-ietf-poly1305)、UDP
set -u
NET=ix-ss; PFX=ixs-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}          # 可用 NTR_BIN 覆盖为自编译版
K16=rpZjVevZpPwq13KLjK8zRw==
K32=u8j5keFIHb0H1NFWe2sCH2Nxfz6KBmIKppHpAwPyjow=
CPW=mypassword123

cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup
docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1

pw_for(){ case $1 in 2022-blake3-aes-128-gcm) echo "$K16";; 2022-blake3-aes-256-gcm) echo "$K32";; *) echo "$CPW";; esac; }

# ---- 配置生成器:$1=cipher $2=pw $3=peerhost(client 用) ----
ntr_srv(){ cat <<EOF
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: shadowsocks, method: $1, password: "$2"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
EOF
}
ntr_cli(){ cat <<EOF
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: proxy, server: "$3:10000", layers: [{type: shadowsocks, method: $1, password: "$2"}]}
EOF
}
xray_srv(){ cat <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"shadowsocks","settings":{"method":"$1","password":"$2","network":"tcp,udp"}}],"outbounds":[{"protocol":"freedom"}]}
EOF
}
xray_cli(){ cat <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{"address":"$3","port":10000,"method":"$1","password":"$2"}]}}]}
EOF
}
mihomo_srv(){ cat <<EOF
log-level: silent
mode: direct
listeners:
  - {name: in, type: shadowsocks, listen: 0.0.0.0, port: 10000, password: "$2", cipher: $1, udp: true}
EOF
}
mihomo_cli(){ cat <<EOF
mixed-port: 1080
allow-lan: true
bind-address: "*"
log-level: silent
proxies: [{name: p, type: ss, server: $3, port: 10000, cipher: $1, password: "$2", udp: true}]
rules:
  - MATCH,p
EOF
}
singbox_srv(){ cat <<EOF
{"log":{"level":"error"},"inbounds":[{"type":"shadowsocks","listen":"0.0.0.0","listen_port":10000,"method":"$1","password":"$2"}],"outbounds":[{"type":"direct"}]}
EOF
}
singbox_cli(){ cat <<EOF
{"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"0.0.0.0","listen_port":1080}],"outbounds":[{"type":"shadowsocks","server":"$3","server_port":10000,"method":"$1","password":"$2"}]}
EOF
}

start(){ # $1=name $2=eng $3=cfgfile
  local name=$PFX$1 eng=$2 cfg=$3; docker rm -f $name >/dev/null 2>&1
  case $eng in
    ntr)     docker run -d --name $name --network $NET -v $NTR:/ntr:ro -v $cfg:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    ntrdbg)  docker run -d --name $name --network $NET -e NTR_DEBUG=1 -v $NTR:/ntr:ro -v $cfg:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    xray)    docker run -d --name $name --network $NET -v $cfg:/cfg.json:ro ghcr.io/xtls/xray-core:latest run -c /cfg.json >/dev/null 2>&1;;
    mihomo)  docker run -d --name $name --network $NET -v $cfg:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
    singbox) docker run -d --name $name --network $NET -v $cfg:/etc/sing-box/config.json:ro ghcr.io/sagernet/sing-box:latest run -c /etc/sing-box/config.json >/dev/null 2>&1;;
  esac
}
verify(){ local cn=$PFX$1 ok=0 i; for i in 1 2 3 4 5; do
  docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 -x socks5h://$cn:1080 http://${PFX}target/ 2>/dev/null | grep -q Hostname && { ok=1; break; }; sleep 1; done; echo $ok; }
diaglog(){ local sn=$PFX$1 cn=$PFX$2
  docker logs $sn 2>&1 | grep -iE 'err|fail|panic|invalid|reject|refus|unsupport' | grep -viE 'deprecat|migrat' | tail -2 | sed 's/^/     SRV: /'
  docker logs $cn 2>&1 | grep -iE 'err|fail|panic|invalid|reject|refus|unsupport' | grep -viE 'deprecat|migrat' | tail -2 | sed 's/^/     CLI: /'; }

# gen 名: sgen/cgen 按引擎产 srv/cli 配置
srvcfg(){ local eng=$1 c=$2 p=$3 f=$4; case $eng in ntr) ntr_srv "$c" "$p";; xray) xray_srv "$c" "$p";; mihomo) mihomo_srv "$c" "$p";; singbox) singbox_srv "$c" "$p";; esac > $f; }
clicfg(){ local eng=$1 c=$2 p=$3 h=$4 f=$5; case $eng in ntr) ntr_cli "$c" "$p" "$h";; xray) xray_cli "$c" "$p" "$h";; mihomo) mihomo_cli "$c" "$p" "$h";; singbox) singbox_cli "$c" "$p" "$h";; esac > $f; }

run_case(){ # $1=label $2=srv_eng $3=cli_eng $4=cipher
  local label=$1 se=$2 ce=$3 c=$4 p; p=$(pw_for "$c")
  local tag=${se}_${ce}_${c}; local sn=s_$tag cn=c_$tag
  local scfg=$D/_ixs_s_$tag.cfg ccfg=$D/_ixs_c_$tag.cfg
  srvcfg $se "$c" "$p" $scfg
  start $sn $se $scfg; sleep 2
  clicfg $ce "$c" "$p" "$PFX$sn" $ccfg
  start $cn $ce $ccfg; sleep 2
  local ok=$(verify $cn)
  if [ "$ok" = 1 ]; then printf "  \342\234\205 %s\n" "$label"; else printf "  \342\235\214 %s\n" "$label"; diaglog $sn $cn; fi
  docker rm -f $PFX$sn $PFX$cn >/dev/null 2>&1
}

for CIPHER in 2022-blake3-aes-128-gcm 2022-blake3-aes-256-gcm aes-256-gcm chacha20-ietf-poly1305; do
  echo "===== $CIPHER ====="
  run_case "NTR->xray    (NTR client, xray srv)"    xray    ntr     "$CIPHER"
  run_case "xray->NTR    (xray client, NTR srv)"    ntr     xray    "$CIPHER"
  run_case "NTR->mihomo  (NTR client, mihomo srv)"  mihomo  ntr     "$CIPHER"
  run_case "mihomo->NTR  (mihomo client, NTR srv)"  ntr     mihomo  "$CIPHER"
  run_case "NTR->singbox (NTR client, sing-box srv)" singbox ntr    "$CIPHER"
  run_case "singbox->NTR (sing-box client, NTR srv)" ntr    singbox "$CIPHER"
done

cleanup
echo "DONE"
