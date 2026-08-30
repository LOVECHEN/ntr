#!/bin/bash
# 域名嗅探验证:客户端把目标当【IP】交给 NTR(socks5 本地解析,非 socks5h),但 TLS ClientHello 里带 SNI 域名。
# NTR 开 sniff → peek 首包解出 SNI → 按域名分流(domain-suffix)。证「只见 IP 的连接也能按域名分流」。
# ① SNI=blocked.test → 命中 block → 000;② SNI=allowed.test → default direct → 连 TLS 靶机 200;
# ③ sniff 关 → 同样 SNI=blocked.test 也只按 IP 走 default direct → 200(反证:分流确实靠 sniff 出的域名)。
set -u
NET=ixsniff; PFX=ixsniff-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
CURL=curlimages/curl:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
# 共享自签证书(CI workflow 已备;本地缺则生成,chmod 644 供 python 非 root 读)
[ -s "$D/cert.pem" ] || docker run --rm -v $D:/w -w /w alpine sh -c 'apk add -q openssl>/dev/null 2>&1; openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 90 -nodes -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com" >/dev/null 2>&1; chmod 644 cert.pem key.pem'
cleanup; docker network create $NET >/dev/null 2>&1
# TLS 靶机:python https(自签),回 200
docker run -d --name ${PFX}tgt --network $NET -v $D/cert.pem:/c.pem:ro -v $D/key.pem:/k.pem:ro python:3-alpine sh -c "cd /; python3 -c \"
import http.server,ssl
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain('/c.pem','/k.pem')
h=http.server.HTTPServer(('0.0.0.0',443),http.server.BaseHTTPRequestHandler)
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(b'SNIFFOK')
h.RequestHandlerClass=H; h.socket=c.wrap_socket(h.socket,server_side=True); h.serve_forever()\"" >/dev/null 2>&1
sleep 2
TGT=$(docker inspect ${PFX}tgt --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
echo "TLS 靶机 TGT=$TGT"
# NTR:socks 入站(开 sniff)+ 路由 domain-suffix blocked.test→block
mkntr(){ cat > $D/_sniff_$1.yaml <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], sniff: $2, outbound: direct}
outbounds:
  - {name: direct, type: direct}
  - {name: block, type: block}
routing:
  default: direct
  rules:
    - {domain-suffix: [blocked.test], to: block}
Y
docker rm -f ${PFX}c >/dev/null 2>&1
docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_sniff_$1.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}c "监听于" 15; }
# curl -x socks5(本地解析,发 IP 给 NTR)+ --resolve 把域名钉到 TGT + -k 跳证书验证;SNI 即 --url 的域名
probe(){ docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -k -x socks5://${PFX}c:1080 --resolve "$1:443:$TGT" "https://$1/" 2>&1; }

echo "=== sniff 开 ==="; mkntr on true
R1=$(probe blocked.test); echo "  [① SNI=blocked.test → sniff → block]  $([ "$R1" = 000 ] && echo PASS || echo "FAIL(http=$R1)")"
# ② 用可被 docker DNS 解析的靶机容器名作 SNI:sniff 出它→不匹配 block→direct→按【嗅探出的域名】解析连通
#   (证 sniff 确实把路由目标从 IP 换成了域名;假域名 allowed.test 会解析失败,故用真能解析的容器名)
R2=$(probe ${PFX}tgt); echo "  [② SNI=靶机域名 → sniff → direct(按域名解析)→ 200]  $([ "$R2" = 200 ] && echo PASS || echo "FAIL(http=$R2)")"
echo "=== sniff 关(反证)==="; mkntr off false
R3=$(probe blocked.test); echo "  [③ sniff 关:blocked.test 只按 IP → direct → 200]  $([ "$R3" = 200 ] && echo PASS || echo "FAIL(http=$R3)")"
cleanup; echo DONE
