#!/bin/bash
# 逻辑组合规则验证:and / or / not(对齐 sing-box logical、mihomo/xray AND-OR-NOT)。
# 一个靶机(多 network-alias,监听 80+443,恒返 200);socks5h 让 NTR 拿到域名按组合规则分流。
# 默认 direct(200);命中 block 出站 → 000。通过 域名×端口 组合区分各算子:
#   A(and): ① tgt:80=and(tgt∧80)命中→block 000  ② tgt:443 端口不符→direct 200  ③ other:80 域名不符→direct 200
#   B(or):  ④ x1:80 命中→block 000  ⑤ x2:443 命中→block 000  ⑥ other:443 不符→direct 200
#   C(not): ⑦ tgt:80 非keep→not命中→block 000  ⑧ keep:80 是keep→not不中→direct 200
set -u
NET=ixlogic; PFX=ixlogic-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
CURL=curlimages/curl:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
cleanup; docker network create $NET >/dev/null 2>&1

# 靶机:监听 80+443(明文),恒 200;多别名都指向它
cat > $D/_logic_tgt.py <<'PY'
import http.server,threading
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(b'OK')
    def log_message(*a): pass
def serve(p): http.server.HTTPServer(('0.0.0.0',p),H).serve_forever()
threading.Thread(target=serve,args=(80,),daemon=True).start()
serve(443)
PY
docker run -d --name ${PFX}tgt --network $NET \
  --network-alias tgt --network-alias other --network-alias x1 --network-alias x2 --network-alias keep \
  -v $D/_logic_tgt.py:/t.py:ro python:3-alpine python3 /t.py >/dev/null 2>&1
sleep 2

mkntr(){ cat > $D/_logic_$1.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: direct
outbounds:
  - name: direct
    type: direct
  - name: block
    type: block
routing:
  default: direct
  rules:
$2
Y
docker rm -f ${PFX}c >/dev/null 2>&1
docker run -d --name ${PFX}c --network-alias cli --network $NET -v $NTR:/ntr:ro -v $D/_logic_$1.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}c "监听于" 15; }

probe(){ docker run --rm --network $NET $CURL -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://cli:1080 "http://$1/" 2>&1; }
chk(){ echo "  [$1]  $([ "$2" = "$3" ] && echo PASS || echo "FAIL(http=$2 期望 $3)")"; }

echo "=== A: and[domain-suffix tgt, port 80] → block ==="
mkntr and '    - op: and
      to: block
      sub:
        - domain-suffix:
            - tgt
        - port:
            - 80'
chk "① tgt:80 and 全中→block"      "$(probe tgt:80)"   000
chk "② tgt:443 端口不符→direct"     "$(probe tgt:443)"  200
chk "③ other:80 域名不符→direct"    "$(probe other:80)" 200

echo "=== B: or[domain x1, domain x2] → block ==="
mkntr or '    - op: or
      to: block
      sub:
        - domain:
            - x1
        - domain:
            - x2'
chk "④ x1:80 or 命中→block"         "$(probe x1:80)"    000
chk "⑤ x2:443 or 命中→block"        "$(probe x2:443)"   000
chk "⑥ other:443 不符→direct"       "$(probe other:443)" 200

echo "=== C: not(or[domain-suffix keep]) → block ==="
mkntr not '    - op: or
      not: true
      to: block
      sub:
        - domain-suffix:
            - keep'
chk "⑦ tgt:80 非keep→not命中→block" "$(probe tgt:80)"   000
chk "⑧ keep:80 是keep→放行→direct"  "$(probe keep:80)"  200

cleanup; echo DONE
