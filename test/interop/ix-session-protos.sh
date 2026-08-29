#!/bin/bash
# 组 7 回归:AnyTLS + NaiveProxy + TrustTunnel 双向互通
# 对端:sing-box 1.13.19 (anytls/naive) + mihomo v1.19.30 (anytls/trusttunnel)
# 专属 network=ix-se 容器前缀=ixe-。禁改协议线格式;失败先查测试配置。
set -u
NET=ix-se; PFX=ixe-; D=/tmp/ntr-interop
SB=ghcr.io/sagernet/sing-box:latest
MH=metacubex/mihomo:latest
CURL=curlimages/curl:latest
# 探测重试至就绪:CI 冷 runner 上对端服务端起得慢,固定 sleep 常不够;成功(拿 Hostname)即早退。
dial(){ local i out; for i in 1 2 3 4 5 6; do out=$(docker run --rm --network $NET $CURL -s --max-time 12 "$@" 2>&1); echo "$out" | grep -q Hostname && { echo "$out"; return; }; sleep 1.5; done; echo "$out"; }
PA="--platform linux/amd64"   # ntr=amd64;对端/靶机用本机原生 arch
U=u; PW=sesspw123

cleanup(){ docker ps -aq --filter "name=^${PFX}" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
cleanup
docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null

hit(){ # $1=curl输出 $2=键 $3=描述
  if echo "$1" | grep -q Hostname; then eval "R_$2='✅通'"; echo "  ✅ $3: $(echo "$1"|grep -i Hostname|tr -d '\r')";
  else eval "R_$2='❌不通'"; echo "  ❌ $3"; return 1; fi
}
dbg(){ echo "     --- $1 log ---"; docker logs "$1" 2>&1 | tail -"${2:-10}"; }

# mihomo SAFE_PATHS:证书内联进 yaml
CERT_IND=$(sed 's/^/      /' $D/cert.pem); KEY_IND=$(sed 's/^/      /' $D/key.pem)

########################################################################
echo "════════ 1. AnyTLS ⇄ sing-box ════════"
# --- 1A: NTR anytls 客户端 → sing-box anytls 服务端 ---
printf '{"log":{"level":"warn"},"inbounds":[{"type":"anytls","listen":"::","listen_port":8443,"users":[{"password":"%s"}],"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem"}}],"outbounds":[{"type":"direct"}]}\n' "$PW" > $D/ix-sb-at-srv.json
docker run -d --name ${PFX}sb-at-srv --network $NET -v $D/ix-sb-at-srv.json:/c.json:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro $SB -c /c.json run >/dev/null 2>&1
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: at}\noutbounds:\n  - {name: at, type: anytls, server: "%ssb-at-srv:8443", secret: "%s", sni: example.com, insecure: true}\n' "$PFX" "$PW" > $D/ix-ntr-at-cli.yaml
docker run -d --name ${PFX}ntr-at-cli --network $NET $PA -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ix-ntr-at-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
hit "$(dial -x socks5h://${PFX}ntr-at-cli:1080 http://${PFX}target/)" AT_SB_A "1A anytls NTR客户端→sing-box服务端" || { dbg ${PFX}sb-at-srv; dbg ${PFX}ntr-at-cli; }

# --- 1B: sing-box anytls 客户端 → NTR anytls 服务端 ---
printf 'inbounds:\n  - listen: 0.0.0.0:8443\n    type: anytls\n    users: [{password: "%s"}]\n    tls: {cert-file: /cert.pem, key-file: /key.pem}\n    outbound: direct\noutbounds: [{name: direct, type: direct}]\n' "$PW" > $D/ix-ntr-at-srv.yaml
docker run -d --name ${PFX}ntr-at-srv --network $NET $PA -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ix-ntr-at-srv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
printf '{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"anytls","server":"%sntr-at-srv","server_port":8443,"password":"%s","tls":{"enabled":true,"server_name":"example.com","insecure":true}}]}\n' "$PFX" "$PW" > $D/ix-sb-at-cli.json
docker run -d --name ${PFX}sb-at-cli --network $NET -v $D/ix-sb-at-cli.json:/c.json:ro $SB -c /c.json run >/dev/null 2>&1
sleep 5
hit "$(dial -x http://${PFX}sb-at-cli:1080 http://${PFX}target/)" AT_SB_B "1B anytls sing-box客户端→NTR服务端" || { dbg ${PFX}ntr-at-srv; dbg ${PFX}sb-at-cli; }

########################################################################
echo "════════ 2. AnyTLS ⇄ mihomo ════════"
# --- 2A: NTR anytls 客户端 → mihomo anytls 服务端 ---
cat > $D/ix-mh-at-srv.yaml <<EOF
log-level: warning
mode: rule
listeners:
  - name: at-in
    type: anytls
    port: 8443
    listen: 0.0.0.0
    users:
      $U: "$PW"
    certificate: |
$CERT_IND
    private-key: |
$KEY_IND
proxies: []
rules:
  - MATCH,DIRECT
EOF
docker run -d --name ${PFX}mh-at-srv --network $NET -v $D/ix-mh-at-srv.yaml:/root/.config/mihomo/config.yaml:ro $MH >/dev/null 2>&1
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: at}\noutbounds:\n  - {name: at, type: anytls, server: "%smh-at-srv:8443", secret: "%s", sni: example.com, insecure: true}\n' "$PFX" "$PW" > $D/ix-ntr-at-cli2.yaml
docker run -d --name ${PFX}ntr-at-cli2 --network $NET $PA -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ix-ntr-at-cli2.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
hit "$(dial -x socks5h://${PFX}ntr-at-cli2:1080 http://${PFX}target/)" AT_MH_A "2A anytls NTR客户端→mihomo服务端" || { dbg ${PFX}mh-at-srv; dbg ${PFX}ntr-at-cli2; }

# --- 2B: mihomo anytls 客户端 → NTR anytls 服务端(复用 1B 的 NTR srv) ---
cat > $D/ix-mh-at-cli.yaml <<EOF
mixed-port: 1080
allow-lan: true
log-level: warning
mode: rule
proxies:
  - name: p
    type: anytls
    server: ${PFX}ntr-at-srv
    port: 8443
    password: "$PW"
    sni: example.com
    skip-cert-verify: true
    udp: true
rules:
  - MATCH,p
EOF
docker run -d --name ${PFX}mh-at-cli --network $NET -v $D/ix-mh-at-cli.yaml:/root/.config/mihomo/config.yaml:ro $MH >/dev/null 2>&1
sleep 5
hit "$(dial -x http://${PFX}mh-at-cli:1080 http://${PFX}target/)" AT_MH_B "2B anytls mihomo客户端→NTR服务端" || { dbg ${PFX}ntr-at-srv; dbg ${PFX}mh-at-cli; }

########################################################################
echo "════════ 3. NaiveProxy ⇄ sing-box(cronet)════════"
# --- 3A: NTR naive 客户端 → sing-box naive 服务端 ---
printf '{"log":{"level":"warn"},"inbounds":[{"type":"naive","listen":"::","listen_port":8443,"users":[{"username":"%s","password":"%s"}],"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem"}}],"outbounds":[{"type":"direct"}]}\n' "$U" "$PW" > $D/ix-sb-nv-srv.json
docker run -d --name ${PFX}sb-nv-srv --network $NET -v $D/ix-sb-nv-srv.json:/c.json:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro $SB -c /c.json run >/dev/null 2>&1
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: naive, server: "%ssb-nv-srv:8443", user: %s, secret: "%s", sni: example.com, insecure: true}\n' "$PFX" "$U" "$PW" > $D/ix-ntr-nv-cli.yaml
docker run -d --name ${PFX}ntr-nv-cli --network $NET $PA -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ix-ntr-nv-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
hit "$(dial -x socks5h://${PFX}ntr-nv-cli:1080 http://${PFX}target/)" NV_A "3A naive NTR客户端→sing-box服务端" || { dbg ${PFX}sb-nv-srv; dbg ${PFX}ntr-nv-cli; }

# --- 3B: sing-box naive(cronet)客户端 → NTR naive 服务端 ---
# cronet 不支持 insecure,须信任 CA;NTR 服务端出示 leaf(cert.pem 已是 CA 签的短期叶子)
printf 'inbounds:\n  - listen: 0.0.0.0:8443\n    type: naive\n    tls: {cert-file: /cert.pem, key-file: /key.pem}\n    users: [{name: %s, password: "%s"}]\noutbounds: [{name: direct, type: direct}]\n' "$U" "$PW" > $D/ix-ntr-nv-srv.yaml
docker run -d --name ${PFX}ntr-nv-srv --network $NET $PA -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ix-ntr-nv-srv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
printf '{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"naive","server":"%sntr-nv-srv","server_port":8443,"username":"%s","password":"%s","tls":{"enabled":true,"server_name":"example.com","certificate_path":"/ca.pem"}}]}\n' "$PFX" "$U" "$PW" > $D/ix-sb-nv-cli.json
docker run -d --name ${PFX}sb-nv-cli --network $NET -v $D/ix-sb-nv-cli.json:/c.json:ro -v $D/ca.pem:/ca.pem:ro $SB -c /c.json run >/dev/null 2>&1
sleep 6
hit "$(dial -x http://${PFX}sb-nv-cli:1080 http://${PFX}target/)" NV_B "3B naive sing-box(cronet)客户端→NTR服务端" || { dbg ${PFX}ntr-nv-srv; dbg ${PFX}sb-nv-cli 15; }

########################################################################
echo "════════ 4. TrustTunnel ⇄ mihomo ════════"
# --- 4A: NTR trusttunnel 客户端 → mihomo trusttunnel 服务端 ---
cat > $D/ix-mh-tt-srv.yaml <<EOF
log-level: warning
mode: rule
listeners:
  - name: tt-in
    type: trusttunnel
    port: 8443
    listen: 0.0.0.0
    users:
      - username: $U
        password: $PW
    certificate: |
$CERT_IND
    private-key: |
$KEY_IND
proxies: []
rules:
  - MATCH,DIRECT
EOF
docker run -d --name ${PFX}mh-tt-srv --network $NET -v $D/ix-mh-tt-srv.yaml:/root/.config/mihomo/config.yaml:ro $MH >/dev/null 2>&1
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: trusttunnel, server: "%smh-tt-srv:8443", user: %s, secret: "%s", sni: example.com, insecure: true}\n' "$PFX" "$U" "$PW" > $D/ix-ntr-tt-cli.yaml
docker run -d --name ${PFX}ntr-tt-cli --network $NET $PA -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ix-ntr-tt-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
hit "$(dial -x socks5h://${PFX}ntr-tt-cli:1080 http://${PFX}target/)" TT_A "4A trusttunnel NTR客户端→mihomo服务端" || { dbg ${PFX}mh-tt-srv; dbg ${PFX}ntr-tt-cli; }

# --- 4B: mihomo trusttunnel 客户端 → NTR trusttunnel 服务端 ---
printf 'inbounds:\n  - listen: 0.0.0.0:8443\n    type: trusttunnel\n    tls: {cert-file: /cert.pem, key-file: /key.pem}\n    users: [{name: %s, password: "%s"}]\noutbounds: [{name: direct, type: direct}]\n' "$U" "$PW" > $D/ix-ntr-tt-srv.yaml
docker run -d --name ${PFX}ntr-tt-srv --network $NET $PA -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ix-ntr-tt-srv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
cat > $D/ix-mh-tt-cli.yaml <<EOF
mixed-port: 1080
allow-lan: true
log-level: warning
mode: rule
proxies:
  - name: p
    type: trusttunnel
    server: ${PFX}ntr-tt-srv
    port: 8443
    username: $U
    password: "$PW"
    sni: example.com
    skip-cert-verify: true
    alpn: [h2]
rules:
  - MATCH,p
EOF
docker run -d --name ${PFX}mh-tt-cli --network $NET -v $D/ix-mh-tt-cli.yaml:/root/.config/mihomo/config.yaml:ro $MH >/dev/null 2>&1
sleep 5
hit "$(dial -x http://${PFX}mh-tt-cli:1080 http://${PFX}target/)" TT_B "4B trusttunnel mihomo客户端→NTR服务端" || { dbg ${PFX}ntr-tt-srv; dbg ${PFX}mh-tt-cli 15; }

########################################################################
echo "════════ 5. uTLS 指纹回归:naive/trusttunnel 出站加 client-fingerprint: chrome ════════"
# 5A naive chrome fp → sing-box naive srv(复用 3A 的 sb-nv-srv)
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: naive, server: "%ssb-nv-srv:8443", user: %s, secret: "%s", sni: example.com, insecure: true, client-fingerprint: chrome}\n' "$PFX" "$U" "$PW" > $D/ix-ntr-nv-cli-fp.yaml
docker run -d --name ${PFX}ntr-nv-cli-fp --network $NET $PA -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ix-ntr-nv-cli-fp.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 4
hit "$(dial -x socks5h://${PFX}ntr-nv-cli-fp:1080 http://${PFX}target/)" NV_FP "5A naive(chrome指纹)NTR客户端→sing-box服务端" || { dbg ${PFX}ntr-nv-cli-fp; }

# 5B trusttunnel chrome fp → mihomo trusttunnel srv(复用 4A 的 mh-tt-srv)
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: trusttunnel, server: "%smh-tt-srv:8443", user: %s, secret: "%s", sni: example.com, insecure: true, client-fingerprint: chrome}\n' "$PFX" "$U" "$PW" > $D/ix-ntr-tt-cli-fp.yaml
docker run -d --name ${PFX}ntr-tt-cli-fp --network $NET $PA -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ix-ntr-tt-cli-fp.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 4
hit "$(dial -x socks5h://${PFX}ntr-tt-cli-fp:1080 http://${PFX}target/)" TT_FP "5B trusttunnel(chrome指纹)NTR客户端→mihomo服务端" || { dbg ${PFX}ntr-tt-cli-fp; }

########################################################################
echo ""
echo "════════════════ 结论汇总 ════════════════"
for k in AT_SB_A AT_SB_B AT_MH_A AT_MH_B NV_A NV_B TT_A TT_B NV_FP TT_FP; do
  eval "v=\${R_$k:-未跑}"; echo "  $k = $v"
done
