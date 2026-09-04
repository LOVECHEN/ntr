#!/bin/bash
# ============================================================================
# 组 1:VLESS 全家 —— NTR ⇄ xray-core / mihomo / sing-box 双向互通回归
# 铁律:禁止修改协议线格式。失败先查测试配置,线格式不符则改 NTR 匹配真实现。
# 专属 network=ix-vless;容器前缀=ixv-
# 判据:curl 经 socks5h/http 代理打 whoami 靶机,拿到 Hostname: 行 = 通
# ============================================================================
set -u
D=/tmp/ntr-interop; cd $D
NET=ix-vless
UUID="11111111-1111-1111-1111-111111111111"
# reality x25519(xray 生成的匹配对)
RPRIV="oGDPulZ79UUTcqb3uJNIq4y4cIE8PDxeXjf3cE_pH3s"
RPUB="wunoWy5HhpyAbWzXF7fJbV-NOoK1_b2SCMJAPMb1DFM"
SID="0123456789abcdef"
DEST="www.apple.com:443"
SNIR="www.apple.com"
# xray 26.x 移除了 allowInsecure → 用 pinnedPeerCertificateChainSha256 固定 NTR 服务端叶子证书
PIN=$(openssl x509 -in $D/cert.pem -outform der 2>/dev/null | openssl dgst -sha256 -binary | openssl base64)

RESULTS=()
rec(){ RESULTS+=("$1|$2|$3|$4"); }   # combo|dir|peer|result

clean(){ docker rm -f $(docker ps -aq --filter "name=ixv-") >/dev/null 2>&1; }
netup(){ docker network create $NET >/dev/null 2>&1; }
netdown(){ docker network rm $NET >/dev/null 2>&1; }

# 起 NTR 容器(amd64 二进制在 OrbStack 透明模拟)
ntr(){ # name configfile [extra mounts...]
  local name=$1 cfg=$2; shift 2
  docker run -d --name $name --network $NET -v $D/ntr:/ntr:ro -v $D/$cfg:/c.yaml:ro \
    -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro "$@" \
    alpine /ntr -config /c.yaml >/dev/null 2>&1
}
xray(){ local name=$1 cfg=$2; docker run -d --name $name --network $NET -v $D/$cfg:/c.json:ro \
  -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro -v $D/ca.pem:/ca.pem:ro -e SSL_CERT_FILE=/ca.pem \
  ghcr.io/xtls/xray-core:latest -c /c.json >/dev/null 2>&1; }
mihomo(){ local name=$1 cfg=$2; docker run -d --name $name --network $NET \
  -v $D/$cfg:/root/.config/mihomo/config.yaml:ro \
  -v $D/cert.pem:/root/.config/mihomo/cert.pem:ro -v $D/key.pem:/root/.config/mihomo/key.pem:ro \
  metacubex/mihomo:latest >/dev/null 2>&1; }
singbox(){ local name=$1 cfg=$2; docker run -d --name $name --network $NET -v $D/$cfg:/c.json:ro \
  -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1; }

# 经 socks5h 代理(NTR 客户端 / xray 客户端 / sing-box mixed / mihomo mixed 都用 socks5h)拉靶机
pull(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 15 -x "$1" http://ixv-target/ 2>&1; }
ok(){ echo "$1" | grep -q Hostname && echo PASS || echo FAIL; }

target(){ docker run -d --name ixv-target --network $NET traefik/whoami >/dev/null 2>&1; }

# ============================================================================
# 配置生成器
# ============================================================================
# --- NTR 客户端(socks 入 → vless 出),$1=combo: none/tls/reality/vision ---
# 层块(SEC:tls/reality 安全层)与协议字段(FLOW:vless flow)拆成条件多行块,插入 up 出站(4 空格缩进)。
gen_ntr_cli(){ local combo=$1 srv=$2 out=$3 SEC="" FLOW=""
  case $combo in
   none)   SEC="";;
   tls)    SEC=$'    tls:\n      sni: example.com\n      insecure: true\n';;
   reality)SEC=$'    reality:\n      public-key: "'$RPUB$'"\n      server-name: "'$SNIR$'"\n      short-id: "'$SID$'"\n      fingerprint: chrome\n';;
   vision) SEC=$'    tls:\n      sni: example.com\n      insecure: true\n'; FLOW=$'    flow: xtls-rprx-vision\n';;
   vision-reality) SEC=$'    reality:\n      public-key: "'$RPUB$'"\n      server-name: "'$SNIR$'"\n      short-id: "'$SID$'"\n      fingerprint: chrome\n'; FLOW=$'    flow: xtls-rprx-vision\n';;
  esac
  printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: vless\n    server: "%s:10000"\n    secret: "%s"\n%s%s' "$srv" "$UUID" "$FLOW" "$SEC" > $out
}
# --- NTR 服务端(vless 入 → direct),$1=combo ---
gen_ntr_srv(){ local combo=$1 out=$2 SEC=""
  case $combo in
   none)   SEC="";;
   tls)    SEC=$'    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n';;
   reality)SEC=$'    reality:\n      private-key: "'$RPRIV$'"\n      dest: "'$DEST$'"\n      server-name: "'$SNIR$'"\n      short-id: "'$SID$'"\n';;
   vision) SEC=$'    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n';;
   vision-reality) SEC=$'    reality:\n      private-key: "'$RPRIV$'"\n      dest: "'$DEST$'"\n      server-name: "'$SNIR$'"\n      short-id: "'$SID$'"\n';;
  esac
  printf 'inbounds:\n  - name: vless-in\n    type: vless\n    listen: 0.0.0.0:10000\n%s    users:\n      - uuid: "%s"\n    outbound: direct\noutbounds:\n  - name: direct\n    type: direct\n' "$SEC" "$UUID" > $out
}

# --- xray 服务端 ---
gen_xray_srv(){ local combo=$1 out=$2 flow="" ss=""
  case $combo in
   none)    ss='"security":"none"';;
   tls)     ss='"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/cert.pem","keyFile":"/key.pem"}]}';;
   reality) ss='"security":"reality","realitySettings":{"dest":"'$DEST'","serverNames":["'$SNIR'"],"privateKey":"'$RPRIV'","shortIds":["'$SID'"]}';;
   vision)  ss='"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/cert.pem","keyFile":"/key.pem"}]}'; flow=',"flow":"xtls-rprx-vision"';;
   vision-reality) ss='"security":"reality","realitySettings":{"dest":"'$DEST'","serverNames":["'$SNIR'"],"privateKey":"'$RPRIV'","shortIds":["'$SID'"]}'; flow=',"flow":"xtls-rprx-vision"';;
  esac
  printf '{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"vless","settings":{"clients":[{"id":"%s"%s}],"decryption":"none"},"streamSettings":{"network":"tcp",%s}}],"outbounds":[{"protocol":"freedom"}]}\n' "$UUID" "$flow" "$ss" > $out
}
# --- xray 客户端(socks 1080 → vless) ---
gen_xray_cli(){ local combo=$1 srv=$2 out=$3 flow="" ss=""
  case $combo in
   none)    ss='"security":"none"';;
   tls)     ss='"security":"tls","tlsSettings":{"serverName":"example.com"}';;
   reality) ss='"security":"reality","realitySettings":{"serverName":"'$SNIR'","publicKey":"'$RPUB'","shortId":"'$SID'","fingerprint":"chrome"}';;
   vision)  ss='"security":"tls","tlsSettings":{"serverName":"example.com"}'; flow=',"flow":"xtls-rprx-vision"';;
   vision-reality) ss='"security":"reality","realitySettings":{"serverName":"'$SNIR'","publicKey":"'$RPUB'","shortId":"'$SID'","fingerprint":"chrome"}'; flow=',"flow":"xtls-rprx-vision"';;
  esac
  printf '{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true,"auth":"noauth"}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"%s","port":10000,"users":[{"id":"%s","encryption":"none"%s}]}]},"streamSettings":{"network":"tcp",%s}}]}\n' "$srv" "$UUID" "$flow" "$ss" > $out
}

# --- mihomo 服务端(listeners vless-in) ---
gen_mihomo_srv(){ local combo=$1 out=$2 tls="" flow=""
  case $combo in
   none)   tls=$'    allow-insecure: true\n';;   # mihomo 拒绝无任何安全配置的明文 vless 入站,allow-insecure 解锁明文
   tls)    tls=$'    certificate: /root/.config/mihomo/cert.pem\n    private-key: /root/.config/mihomo/key.pem\n';;
   reality)tls=$'    reality-config:\n      dest: '$DEST$'\n      private-key: '$RPRIV$'\n      short-id:\n        - '$SID$'\n      server-names:\n        - '$SNIR$'\n';;
   vision) tls=$'    certificate: /root/.config/mihomo/cert.pem\n    private-key: /root/.config/mihomo/key.pem\n'; flow=$'        flow: xtls-rprx-vision\n';;
   vision-reality) tls=$'    reality-config:\n      dest: '$DEST$'\n      private-key: '$RPRIV$'\n      short-id:\n        - '$SID$'\n      server-names:\n        - '$SNIR$'\n'; flow=$'        flow: xtls-rprx-vision\n';;
  esac
  { printf 'log-level: warning\nlisteners:\n  - name: vless-in\n    type: vless\n    port: 10000\n    listen: 0.0.0.0\n    users:\n      - username: u\n        uuid: %s\n%s%s' "$UUID" "$flow" "$tls"
  } > $out
}
# --- mihomo 客户端(mixed 1080 → vless) ---
gen_mihomo_cli(){ local combo=$1 srv=$2 out=$3 extra="" flow=""
  case $combo in
   none)   extra=$'    tls: false\n';;
   tls)    extra=$'    tls: true\n    servername: example.com\n    skip-cert-verify: true\n';;
   reality)extra=$'    tls: true\n    servername: '$SNIR$'\n    reality-opts:\n      public-key: '$RPUB$'\n      short-id: '$SID$'\n    client-fingerprint: chrome\n';;
   vision) extra=$'    tls: true\n    servername: example.com\n    skip-cert-verify: true\n    flow: xtls-rprx-vision\n';;
   vision-reality) extra=$'    tls: true\n    servername: '$SNIR$'\n    reality-opts:\n      public-key: '$RPUB$'\n      short-id: '$SID$'\n    client-fingerprint: chrome\n    flow: xtls-rprx-vision\n';;
  esac
  { printf 'log-level: warning\nmixed-port: 1080\nallow-lan: true\nproxies:\n  - name: vl-out\n    type: vless\n    server: %s\n    port: 10000\n    uuid: %s\n    network: tcp\n    udp: true\n%srules:\n  - MATCH,vl-out\n' "$srv" "$UUID" "$extra"
  } > $out
}

# --- sing-box 服务端 ---
gen_sb_srv(){ local combo=$1 out=$2 flow="" tls=""
  case $combo in
   none)   tls='';;
   tls)    tls=',"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem"}';;
   reality)tls=',"tls":{"enabled":true,"server_name":"'$SNIR'","reality":{"enabled":true,"handshake":{"server":"'${DEST%%:*}'","server_port":443},"private_key":"'$RPRIV'","short_id":["'$SID'"]}}';;
   vision) tls=',"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem"}'; flow=',"flow":"xtls-rprx-vision"';;
   vision-reality) tls=',"tls":{"enabled":true,"server_name":"'$SNIR'","reality":{"enabled":true,"handshake":{"server":"'${DEST%%:*}'","server_port":443},"private_key":"'$RPRIV'","short_id":["'$SID'"]}}'; flow=',"flow":"xtls-rprx-vision"';;
  esac
  printf '{"log":{"level":"warn"},"inbounds":[{"type":"vless","listen":"::","listen_port":10000,"users":[{"uuid":"%s"%s}]%s}],"outbounds":[{"type":"direct"}]}\n' "$UUID" "$flow" "$tls" > $out
}
# --- sing-box 客户端(mixed 1080 → vless) ---
gen_sb_cli(){ local combo=$1 srv=$2 out=$3 flow="" tls=""
  case $combo in
   none)   tls='';;
   tls)    tls=',"tls":{"enabled":true,"server_name":"example.com","insecure":true}';;
   reality)tls=',"tls":{"enabled":true,"server_name":"'$SNIR'","reality":{"enabled":true,"public_key":"'$RPUB'","short_id":"'$SID'"},"utls":{"enabled":true,"fingerprint":"chrome"}}';;
   vision) tls=',"tls":{"enabled":true,"server_name":"example.com","insecure":true}'; flow=',"flow":"xtls-rprx-vision"';;
   vision-reality) tls=',"tls":{"enabled":true,"server_name":"'$SNIR'","reality":{"enabled":true,"public_key":"'$RPUB'","short_id":"'$SID'"},"utls":{"enabled":true,"fingerprint":"chrome"}}'; flow=',"flow":"xtls-rprx-vision"';;
  esac
  printf '{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"vless","server":"%s","server_port":10000,"uuid":"%s"%s%s}]}\n' "$srv" "$UUID" "$flow" "$tls" > $out
}

# ============================================================================
# 驱动:一个 (combo,peer) 的双向测试
# ============================================================================
# A 方向:NTR 客户端 → 对端服务端
dirA(){ local combo=$1 peer=$2 wait=${3:-6}
  clean
  target
  case $peer in
   xray)   gen_xray_srv $combo A-srv.json; xray ixv-srv A-srv.json;;
   mihomo) gen_mihomo_srv $combo A-srv.yaml; mihomo ixv-srv A-srv.yaml;;
   singbox)gen_sb_srv $combo A-srv.json; singbox ixv-srv A-srv.json;;
  esac
  sleep 2
  gen_ntr_cli $combo ixv-srv A-cli.yaml; ntr ixv-cli A-cli.yaml
  sleep $wait
  local r=$(ok "$(pull socks5h://ixv-cli:1080)")
  [ "$r" = FAIL ] && { echo "   [A $combo $peer FAIL] srv-log:"; docker logs ixv-srv 2>&1 | tail -4 | sed 's/^/     /'; echo "   cli-log:"; docker logs ixv-cli 2>&1 | tail -6 | sed 's/^/     /'; }
  rec "$combo" "NTR→${peer}" "$peer" "$r"
}
# B 方向:对端客户端 → NTR 服务端
dirB(){ local combo=$1 peer=$2 wait=${3:-6}
  clean
  target
  gen_ntr_srv $combo B-srv.yaml; ntr ixv-srv B-srv.yaml
  sleep 2
  case $peer in
   xray)   gen_xray_cli $combo ixv-srv B-cli.json; xray ixv-cli B-cli.json;;
   mihomo) gen_mihomo_cli $combo ixv-srv B-cli.yaml; mihomo ixv-cli B-cli.yaml;;
   singbox)gen_sb_cli $combo ixv-srv B-cli.json; singbox ixv-cli B-cli.json;;
  esac
  sleep $wait
  local r=$(ok "$(pull socks5h://ixv-cli:1080)")
  [ "$r" = FAIL ] && { echo "   [B $combo $peer FAIL] ntrsrv-log:"; docker logs ixv-srv 2>&1 | tail -6 | sed 's/^/     /'; echo "   peercli-log:"; docker logs ixv-cli 2>&1 | tail -6 | sed 's/^/     /'; }
  rec "$combo" "${peer}→NTR" "$peer" "$r"
}

run_all(){
  netup
  for combo in none tls reality vision vision-reality; do
    for peer in xray mihomo singbox; do
      echo "== $combo / $peer =="
      dirA $combo $peer
      dirB $combo $peer
    done
  done
  clean; netdown
  echo; echo "════════════════ 结论表 ════════════════"
  printf "%-16s %-14s %-8s %s\n" combo dir peer result
  for r in "${RESULTS[@]}"; do IFS='|' read -r c d p res <<<"$r"; printf "%-16s %-14s %-8s %s\n" "$c" "$d" "$p" "$res"; done
}

"${@:-run_all}"
