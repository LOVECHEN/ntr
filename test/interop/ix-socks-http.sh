#!/bin/bash
# 组 8:SOCKS / HTTP / mixed —— NTR ⇄ xray / mihomo / sing-box / 真 curl 双向互通回归。
# 专属 network: ix-sh ; 容器前缀: ixh-
# 铁律:禁改协议线格式。失败先查测试配置;线格式不符才改 NTR 匹配真实现。
set -u
D=/tmp/ntr-interop; cd $D
NET=ix-sh
NTR=$D/ntr
CURL="curlimages/curl:latest"

# ---------- 自包含内联生成 python 助手 ----------
# CI 每个 ix-*.sh 是隔离 job,$D 里只有 workflow 放的 ntr binary + cert,没有前序产物。
# 不内联则 docker run -v $D/xxx.py 把「不存在的单文件」挂成空目录 → python: can't find '__main__' module。
cat > $D/udpecho.py <<'UDPECHO'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',9999))
while True:
    d,a=s.recvfrom(4096); s.sendto(d,a)
UDPECHO
cat > $D/ix-socksudp.py <<'SOCKSUDP'
import socket,struct,sys
# argv: proxy_host target_host [msg]
proxy=(sys.argv[1],1080); target=(sys.argv[2],9999)
msg=(sys.argv[3] if len(sys.argv)>3 else 'PINGUDP-socks-42').encode()
tcp=socket.create_connection(proxy,timeout=6)
tcp.sendall(b'\x05\x01\x00')
if tcp.recv(2)!=b'\x05\x00': print('greet fail'); sys.exit(2)
tcp.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
r=tcp.recv(10)
if r[1]!=0: print('associate fail',r); sys.exit(3)
bnd_ip=socket.inet_ntoa(r[4:8]); bnd_port=struct.unpack('>H',r[8:10])[0]
if bnd_ip in ('0.0.0.0','127.0.0.1'): bnd_ip=proxy[0]
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.settimeout(6)
th=target[0].encode()
pkt=b'\x00\x00\x00\x03'+bytes([len(th)])+th+struct.pack('>H',target[1])+msg
udp.sendto(pkt,(bnd_ip,bnd_port))
data,_=udp.recvfrom(4096)
atyp=data[3]
off=10 if atyp==1 else (22 if atyp==4 else 4+1+data[4]+2)
payload=data[off:]
print('GOT',payload)
sys.exit(0 if payload==msg else 1)
SOCKSUDP

# ---------- 基础设施 ----------
setup(){
  docker network create $NET >/dev/null 2>&1
  docker rm -f ixh-whoami ixh-echo >/dev/null 2>&1
  docker run -d --name ixh-whoami --network $NET traefik/whoami >/dev/null
  docker run -d --name ixh-echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null
  sleep 1
}
teardown_all(){
  docker ps -a --format '{{.Names}}' | grep '^ixh-' | xargs -r docker rm -f >/dev/null 2>&1
  docker network rm $NET >/dev/null 2>&1
}
# 启一个 NTR 容器
ntr_up(){ # name cfgfile [extra mounts...]
  local name=$1 cfg=$2; shift 2
  docker rm -f $name >/dev/null 2>&1
  docker run -d --name $name --network $NET -v $NTR:/ntr:ro -v $D/$cfg:/c.yaml:ro "$@" alpine /ntr -config /c.yaml >/dev/null 2>&1
}
hit(){ echo "$1" | grep -q "Hostname:" && echo "  ✅ $2" || { echo "  ❌ $2"; [ -n "${3:-}" ] && echo "     └ $(echo "$1"|tr '\n' ' '|cut -c1-160)"; }; }

PASS=0; FAIL=0
ok(){ echo "  ✅ $1"; PASS=$((PASS+1)); }
no(){ echo "  ❌ $1"; FAIL=$((FAIL+1)); }
judge(){ if echo "$1"|grep -q "Hostname:"; then ok "$2"; else no "$2 :: $(echo "$1"|tr '\n' ' '|cut -c1-140)"; fi; }

# =========================================================================
# 1. SOCKS5 服务端(对端/curl 作 socks 客户端 → NTR socks 入站)
# =========================================================================
t_socks5_server(){
  echo "── [1] SOCKS5 server (对端→NTR) ──"
  printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}\noutbounds: [{name: direct, type: direct}]\n' > ix-s5srv.yaml
  ntr_up ixh-s5srv ix-s5srv.yaml
  sleep 1
  # baseline: 真 curl socks5h
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x socks5h://ixh-s5srv:1080 http://ixh-whoami/ 2>&1)" "curl socks5h → NTR"

  # xray socks 出站 → NTR socks 入站(前置 http 入站给 curl 打)
  printf '{"inbounds":[{"port":3080,"listen":"0.0.0.0","protocol":"http"}],"outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"ixh-s5srv","port":1080}]}}]}\n' > ix-xr-s5c.json
  docker rm -f ixh-xr-s5c >/dev/null 2>&1
  docker run -d --name ixh-xr-s5c --network $NET -v $D/ix-xr-s5c.json:/c.json:ro ghcr.io/xtls/xray-core:latest -c /c.json >/dev/null 2>&1
  sleep 1
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x http://ixh-xr-s5c:3080 http://ixh-whoami/ 2>&1)" "xray socks-out → NTR"

  # mihomo socks5 代理 → NTR socks 入站
  printf 'mixed-port: 3080\nallow-lan: true\nlog-level: warning\nproxies:\n  - {name: p, type: socks5, server: ixh-s5srv, port: 1080}\nrules:\n  - MATCH,p\n' > ix-mh-s5c.yaml
  docker rm -f ixh-mh-s5c >/dev/null 2>&1
  docker run -d --name ixh-mh-s5c --network $NET -v $D/ix-mh-s5c.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
  sleep 2
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x http://ixh-mh-s5c:3080 http://ixh-whoami/ 2>&1)" "mihomo socks5-out → NTR"

  # sing-box socks 出站 → NTR socks 入站
  printf '{"inbounds":[{"type":"mixed","listen":"::","listen_port":3080}],"outbounds":[{"type":"socks","server":"ixh-s5srv","server_port":1080,"version":"5"}]}\n' > ix-sb-s5c.json
  docker rm -f ixh-sb-s5c >/dev/null 2>&1
  docker run -d --name ixh-sb-s5c --network $NET -v $D/ix-sb-s5c.json:/c.json:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1
  sleep 1
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x http://ixh-sb-s5c:3080 http://ixh-whoami/ 2>&1)" "sing-box socks-out → NTR"
  docker rm -f ixh-xr-s5c ixh-mh-s5c ixh-sb-s5c >/dev/null 2>&1
}

# =========================================================================
# 2. SOCKS5 客户端(NTR socks 出站)—— NTR 未实现 socks Client,预期 config 构建失败
# =========================================================================
t_socks5_client(){
  echo "── [2] SOCKS5 client (NTR socks 出站 → 上游 socks) ──"
  # NTR SOCKS5 出站(proxy.Client,601f42b:SOCKS5 出站 + UDP ASSOCIATE):NTR 作 socks 客户端连
  # 上游 socks 服务端(复用 [1] 的 ixh-s5srv)→ 落地。socks 出站已实现,此处正向验证其可用。
  docker ps --format '{{.Names}}'|grep -q '^ixh-s5srv$' || { printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}\noutbounds: [{name: direct, type: direct}]\n' > ix-s5srv.yaml; ntr_up ixh-s5srv ix-s5srv.yaml; sleep 1; }
  printf 'inbounds:\n  - {listen: 0.0.0.0:2080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: proxy, server: "ixh-s5srv:1080", layers: [{type: socks}]}\n' > ix-s5cli.yaml
  ntr_up ixh-s5cli ix-s5cli.yaml; sleep 1
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x socks5h://ixh-s5cli:2080 http://ixh-whoami/ 2>&1)" "NTR socks 出站 → 上游 NTR socks 入站 → whoami"
}

# =========================================================================
# 3. SOCKS4 / 4a 服务端
# =========================================================================
t_socks4(){
  echo "── [3] SOCKS4/4a server ──"
  # 复用 [1] 的 ixh-s5srv(socks 入站同时支持 4/4a/5)
  docker ps --format '{{.Names}}'|grep -q '^ixh-s5srv$' || { printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}\noutbounds: [{name: direct, type: direct}]\n' > ix-s5srv.yaml; ntr_up ixh-s5srv ix-s5srv.yaml; sleep 1; }
  # curl --socks4a(域名交代理解析 = 4a)
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 --socks4a ixh-s5srv:1080 http://ixh-whoami/ 2>&1)" "curl socks4a → NTR"
  # curl --socks4(本地解析域名成 IP 再发 = socks4 纯 IP)
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 --socks4 ixh-s5srv:1080 http://ixh-whoami/ 2>&1)" "curl socks4 → NTR"
  # sing-box socks 出站 version 4a → NTR
  printf '{"inbounds":[{"type":"mixed","listen":"::","listen_port":3080}],"outbounds":[{"type":"socks","server":"ixh-s5srv","server_port":1080,"version":"4a"}]}\n' > ix-sb-s4c.json
  docker rm -f ixh-sb-s4c >/dev/null 2>&1
  docker run -d --name ixh-sb-s4c --network $NET -v $D/ix-sb-s4c.json:/c.json:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1
  sleep 1
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x http://ixh-sb-s4c:3080 http://ixh-whoami/ 2>&1)" "sing-box socks4a-out → NTR"
  docker rm -f ixh-sb-s4c >/dev/null 2>&1
}

# =========================================================================
# 4. HTTP CONNECT 双向
# =========================================================================
t_http(){
  echo "── [4] HTTP proxy 双向 ──"
  # 4A: NTR http 入站(server)
  printf 'inbounds:\n  - {listen: 0.0.0.0:8080, layers: [{type: http}], outbound: direct}\noutbounds: [{name: direct, type: direct}]\n' > ix-httpsrv.yaml
  ntr_up ixh-httpsrv ix-httpsrv.yaml; sleep 1
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x http://ixh-httpsrv:8080 http://ixh-whoami/ 2>&1)" "curl http(forward) → NTR"
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -p -x http://ixh-httpsrv:8080 http://ixh-whoami/ 2>&1)" "curl http(CONNECT -p) → NTR"
  # xray http 出站 → NTR http 入站
  printf '{"inbounds":[{"port":3080,"listen":"0.0.0.0","protocol":"socks","settings":{"udp":false}}],"outbounds":[{"protocol":"http","settings":{"servers":[{"address":"ixh-httpsrv","port":8080}]}}]}\n' > ix-xr-hc.json
  docker rm -f ixh-xr-hc >/dev/null 2>&1
  docker run -d --name ixh-xr-hc --network $NET -v $D/ix-xr-hc.json:/c.json:ro ghcr.io/xtls/xray-core:latest -c /c.json >/dev/null 2>&1
  sleep 1
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x socks5h://ixh-xr-hc:3080 http://ixh-whoami/ 2>&1)" "xray http-out → NTR"
  # mihomo http 出站 → NTR http 入站
  printf 'mixed-port: 3080\nallow-lan: true\nlog-level: warning\nproxies:\n  - {name: p, type: http, server: ixh-httpsrv, port: 8080}\nrules:\n  - MATCH,p\n' > ix-mh-hc.yaml
  docker rm -f ixh-mh-hc >/dev/null 2>&1
  docker run -d --name ixh-mh-hc --network $NET -v $D/ix-mh-hc.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
  sleep 2
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x http://ixh-mh-hc:3080 http://ixh-whoami/ 2>&1)" "mihomo http-out → NTR"
  # sing-box http 出站 → NTR http 入站
  printf '{"inbounds":[{"type":"mixed","listen":"::","listen_port":3080}],"outbounds":[{"type":"http","server":"ixh-httpsrv","server_port":8080}]}\n' > ix-sb-hc.json
  docker rm -f ixh-sb-hc >/dev/null 2>&1
  docker run -d --name ixh-sb-hc --network $NET -v $D/ix-sb-hc.json:/c.json:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1
  sleep 1
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x http://ixh-sb-hc:3080 http://ixh-whoami/ 2>&1)" "sing-box http-out → NTR"
  docker rm -f ixh-xr-hc ixh-mh-hc ixh-sb-hc >/dev/null 2>&1

  # 4B: NTR http 出站(client)→ 对端 http 入站。NTR socks 入站给 curl 打。
  # xray http 入站
  printf '{"inbounds":[{"port":8080,"listen":"0.0.0.0","protocol":"http"}],"outbounds":[{"protocol":"freedom"}]}\n' > ix-xr-hs.json
  docker rm -f ixh-xr-hs >/dev/null 2>&1
  docker run -d --name ixh-xr-hs --network $NET -v $D/ix-xr-hs.json:/c.json:ro ghcr.io/xtls/xray-core:latest -c /c.json >/dev/null 2>&1
  printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: proxy, server: "ixh-xr-hs:8080", secret: "", layers: [{type: http}]}\n' > ix-ntr-hc-xr.yaml
  ntr_up ixh-ntr-hc-xr ix-ntr-hc-xr.yaml; sleep 1
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x socks5h://ixh-ntr-hc-xr:1080 http://ixh-whoami/ 2>&1)" "NTR http-out → xray http-in"
  # mihomo http 入站(listener)
  printf 'log-level: warning\nlisteners:\n  - {name: hin, type: http, port: 8080, listen: 0.0.0.0}\n' > ix-mh-hs.yaml
  docker rm -f ixh-mh-hs >/dev/null 2>&1
  docker run -d --name ixh-mh-hs --network $NET -v $D/ix-mh-hs.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
  printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: proxy, server: "ixh-mh-hs:8080", secret: "", layers: [{type: http}]}\n' > ix-ntr-hc-mh.yaml
  ntr_up ixh-ntr-hc-mh ix-ntr-hc-mh.yaml; sleep 2
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x socks5h://ixh-ntr-hc-mh:1080 http://ixh-whoami/ 2>&1)" "NTR http-out → mihomo http-in"
  # sing-box http 入站
  printf '{"inbounds":[{"type":"http","listen":"::","listen_port":8080}],"outbounds":[{"type":"direct"}]}\n' > ix-sb-hs.json
  docker rm -f ixh-sb-hs >/dev/null 2>&1
  docker run -d --name ixh-sb-hs --network $NET -v $D/ix-sb-hs.json:/c.json:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1
  printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: proxy, server: "ixh-sb-hs:8080", secret: "", layers: [{type: http}]}\n' > ix-ntr-hc-sb.yaml
  ntr_up ixh-ntr-hc-sb ix-ntr-hc-sb.yaml; sleep 1
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x socks5h://ixh-ntr-hc-sb:1080 http://ixh-whoami/ 2>&1)" "NTR http-out → sing-box http-in"
  docker rm -f ixh-xr-hs ixh-mh-hs ixh-sb-hs ixh-ntr-hc-xr ixh-ntr-hc-mh ixh-ntr-hc-sb >/dev/null 2>&1
}

# =========================================================================
# 5. mixed 入站(同端口 socks5/socks4a/http)
# =========================================================================
t_mixed(){
  echo "── [5] mixed 入站(同端口)──"
  printf 'inbounds:\n  - {listen: 0.0.0.0:1090, layers: [{type: mixed}], outbound: direct}\noutbounds: [{name: direct, type: direct}]\n' > ix-mixed.yaml
  ntr_up ixh-mixed ix-mixed.yaml; sleep 1
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x socks5h://ixh-mixed:1090 http://ixh-whoami/ 2>&1)" "mixed: curl socks5h"
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 --socks4a ixh-mixed:1090 http://ixh-whoami/ 2>&1)" "mixed: curl socks4a"
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x http://ixh-mixed:1090 http://ixh-whoami/ 2>&1)" "mixed: curl http(forward)"
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -p -x http://ixh-mixed:1090 http://ixh-whoami/ 2>&1)" "mixed: curl http(CONNECT -p)"
  # 第三方作 mixed 客户端:mihomo socks5 出站 → NTR mixed
  printf 'mixed-port: 3080\nallow-lan: true\nlog-level: warning\nproxies:\n  - {name: p, type: socks5, server: ixh-mixed, port: 1090}\nrules:\n  - MATCH,p\n' > ix-mh-mx.yaml
  docker rm -f ixh-mh-mx >/dev/null 2>&1
  docker run -d --name ixh-mh-mx --network $NET -v $D/ix-mh-mx.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
  sleep 2
  judge "$(docker run --rm --network $NET $CURL -s --max-time 10 -x http://ixh-mh-mx:3080 http://ixh-whoami/ 2>&1)" "mixed: mihomo socks5-out → NTR mixed"
  docker rm -f ixh-mh-mx ixh-mixed >/dev/null 2>&1
}

# =========================================================================
# 6. SOCKS UDP ASSOCIATE
# =========================================================================
t_udp(){
  echo "── [6] SOCKS5 UDP ASSOCIATE ──"
  docker ps --format '{{.Names}}'|grep -q '^ixh-s5srv$' || { printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}\noutbounds: [{name: direct, type: direct}]\n' > ix-s5srv.yaml; ntr_up ixh-s5srv ix-s5srv.yaml; sleep 1; }
  out=$(docker run --rm --network $NET -v $D/ix-socksudp.py:/t.py:ro python:3-alpine python /t.py ixh-s5srv ixh-echo 2>&1)
  if echo "$out"|grep -q "GOT b'PINGUDP"; then ok "socks UDP ASSOCIATE (curl-py → NTR → udpecho)"; else no "socks UDP ASSOCIATE :: $out"; fi
  # mixed 入站也测 UDP(mixed→socks 分派)
  printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: mixed}], outbound: direct}\noutbounds: [{name: direct, type: direct}]\n' > ix-mxudp.yaml
  ntr_up ixh-mxudp ix-mxudp.yaml; sleep 1
  out=$(docker run --rm --network $NET -v $D/ix-socksudp.py:/t.py:ro python:3-alpine python /t.py ixh-mxudp ixh-echo 2>&1)
  if echo "$out"|grep -q "GOT b'PINGUDP"; then ok "mixed UDP ASSOCIATE (→ socks 分派)"; else no "mixed UDP ASSOCIATE :: $out"; fi
  docker rm -f ixh-mxudp >/dev/null 2>&1
}

echo "════════ 组 8: SOCKS / HTTP / mixed 互通回归 ════════"
setup
t_socks5_server
t_socks5_client
t_socks4
t_http
t_mixed
t_udp
docker rm -f ixh-s5srv ixh-httpsrv >/dev/null 2>&1
echo "──────────────────────────────────────"
echo "PASS=$PASS FAIL=$FAIL"
teardown_all
