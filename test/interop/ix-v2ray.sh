#!/bin/bash
# ============================================================================
# 组:v2ray-core(v2fly)互通回归 —— NTR ⇄ v2fly/v2ray-core 双向。
# v2ray-core 是 xray 的官方上游/近亲(v2fly 社区版),协议为 xray 子集(无 REALITY/Vision/XTLS)。
# 覆盖两家共有的基础协议:vmess(AEAD)/vless/trojan/shadowsocks,各双向(NTR→v2ray + v2ray→NTR)。
# 铁律:禁改协议线格式。失败先查测试配置;线格式不符才改 NTR 匹配真实现。
# 判据:curl 经 socks5h 打 whoami 靶机,拿到 Hostname 行 = 通。
# 专属 network=ix-v2ray;容器前缀=ixv2-
# ============================================================================
set -u
D=/tmp/ntr-interop; cd $D
NET=ix-v2ray; NTR=${NTR_BIN:-$D/ntr}
UUID="11111111-1111-1111-1111-111111111111"; PW="v2raypass123"; M=aes-256-gcm
V2=v2fly/v2fly-core:latest
RESULTS=()
rec(){ RESULTS+=("$1|$2|$3"); }
clean(){ docker rm -f $(docker ps -aq --filter "name=ixv2-") >/dev/null 2>&1; }
netup(){ docker network create $NET >/dev/null 2>&1; }
netdown(){ docker network rm $NET >/dev/null 2>&1; }
trap 'clean; netdown' EXIT

ntr(){ local name=$1 cfg=$2; docker run -d --name $name --network $NET -v $NTR:/ntr:ro -v $D/$cfg:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
v2ray(){ local name=$1 cfg=$2; docker run -d --name $name --network $NET -v $D/$cfg:/c.json:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro $V2 run -c /c.json >/dev/null 2>&1; }
pull(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://ixv2-cli:1080 http://ixv2-target/ 2>&1; }
ok(){ echo "$1" | grep -q Hostname && echo PASS || echo FAIL; }
target(){ docker run -d --name ixv2-target --network $NET traefik/whoami >/dev/null 2>&1; }

# ---- NTR 客户端(socks 入 → 协议 出);$1=proto ----
gen_ntr_cli(){ local p=$1 out=$2 L
  case $p in
   vmess)  L='[{type: tls, sni: example.com, insecure: true}, {type: vmess, uuid: "'$UUID'"}]';;
   vless)  L='[{type: vless}]';;
   trojan) L='[{type: tls, sni: example.com, insecure: true}, {type: trojan}]';;
   ss)     L='[{type: shadowsocks, method: '$M', password: "'$PW'"}]';;
  esac
  # vless 凭据经 secret(UUID);trojan 经 secret(PW)+ 叠 TLS;vmess/ss 凭据在层内
  local sec=''; case $p in vless) sec='secret: "'$UUID'", ';; trojan) sec='secret: "'$PW'", ';; esac
  printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: proxy, server: "ixv2-srv:10000", %slayers: %s}\n' "$sec" "$L" > $out
}
# ---- NTR 服务端(协议 入 → direct);$1=proto ----
gen_ntr_srv(){ local p=$1 out=$2 L U
  case $p in
   vmess)  L='[{type: tls, cert-file: /cert.pem, key-file: /key.pem}, {type: vmess, uuid: "'$UUID'"}]'; U='';;
   vless)  L='[{type: vless}]'; U='users: [{uuid: "'$UUID'"}]';;
   trojan) L='[{type: tls, cert-file: /cert.pem, key-file: /key.pem}, {type: trojan}]'; U='users: [{password: "'$PW'"}]';;
   ss)     L='[{type: shadowsocks, method: '$M', password: "'$PW'"}]'; U='';;
  esac
  printf 'inbounds:\n  - listen: 0.0.0.0:10000\n    layers: %s\n    %s\n    outbound: direct\noutbounds: [{name: direct, type: direct}]\n' "$L" "$U" > $out
}
# ---- v2ray-core 服务端(协议 入 → freedom)----
gen_v2_srv(){ local p=$1 out=$2 s
  case $p in
   vmess)  s='"protocol":"vmess","settings":{"clients":[{"id":"'$UUID'","alterId":0}]},"streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/cert.pem","keyFile":"/key.pem"}]}}';;
   vless)  s='"protocol":"vless","settings":{"clients":[{"id":"'$UUID'"}],"decryption":"none"}';;
   trojan) s='"protocol":"trojan","settings":{"clients":[{"password":"'$PW'"}]},"streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/cert.pem","keyFile":"/key.pem"}]}}';;
   ss)     s='"protocol":"shadowsocks","settings":{"method":"'$M'","password":"'$PW'","network":"tcp,udp"}';;
  esac
  printf '{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,%s}],"outbounds":[{"protocol":"freedom"}]}\n' "$s" > $out
}
# ---- v2ray-core 客户端(socks 1080 → 协议)----
gen_v2_cli(){ local p=$1 out=$2 s
  case $p in
   vmess)  s='"protocol":"vmess","settings":{"vnext":[{"address":"ixv2-srv","port":10000,"users":[{"id":"'$UUID'","alterId":0,"security":"auto"}]}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","allowInsecure":true}}';;
   vless)  s='"protocol":"vless","settings":{"vnext":[{"address":"ixv2-srv","port":10000,"users":[{"id":"'$UUID'","encryption":"none"}]}]}';;
   trojan) s='"protocol":"trojan","settings":{"servers":[{"address":"ixv2-srv","port":10000,"password":"'$PW'"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","allowInsecure":true}}';;
   ss)     s='"protocol":"shadowsocks","settings":{"servers":[{"address":"ixv2-srv","port":10000,"method":"'$M'","password":"'$PW'"}]}';;
  esac
  printf '{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true,"auth":"noauth"}}],"outbounds":[{%s}]}\n' "$s" > $out
}

# A 向:NTR 客户端 → v2ray 服务端
dirA(){ local p=$1; clean; target
  gen_v2_srv $p A-srv.json; v2ray ixv2-srv A-srv.json; sleep 2
  gen_ntr_cli $p A-cli.yaml; ntr ixv2-cli A-cli.yaml; sleep 3
  local r=$(ok "$(pull)")
  [ "$r" = FAIL ] && { echo "  [A $p FAIL] v2ray-srv:"; docker logs ixv2-srv 2>&1|tail -3|sed 's/^/    /'; echo "  ntr-cli:"; docker logs ixv2-cli 2>&1|tail -3|sed 's/^/    /'; }
  rec "$p" "NTR→v2ray" "$r"
}
# B 向:v2ray 客户端 → NTR 服务端
dirB(){ local p=$1; clean; target
  gen_ntr_srv $p B-srv.yaml; ntr ixv2-srv B-srv.yaml; sleep 2
  gen_v2_cli $p B-cli.json; v2ray ixv2-cli B-cli.json; sleep 3
  local r=$(ok "$(pull)")
  [ "$r" = FAIL ] && { echo "  [B $p FAIL] ntr-srv:"; docker logs ixv2-srv 2>&1|tail -3|sed 's/^/    /'; echo "  v2ray-cli:"; docker logs ixv2-cli 2>&1|tail -3|sed 's/^/    /'; }
  rec "$p" "v2ray→NTR" "$r"
}

netup
echo "### v2ray-core: $(docker run --rm $V2 version 2>/dev/null | head -1)"
for p in vmess vless trojan ss; do
  echo "== $p =="
  dirA $p; dirB $p
done
clean; netdown
echo; echo "════════════ NTR ⇄ v2ray-core 结论 ════════════"
P=0; F=0
printf "%-8s %-14s %s\n" 协议 方向 结果
for r in "${RESULTS[@]}"; do IFS='|' read -r p d res <<<"$r"; printf "%-8s %-14s %s\n" "$p" "$d" "$res"; [ "$res" = PASS ] && P=$((P+1)) || F=$((F+1)); done
echo "──────────── PASS=$P FAIL=$F ────────────"
[ $F -eq 0 ] && echo "✅ NTR ⇄ v2ray-core 全绿" || echo "❌ 有失败"
