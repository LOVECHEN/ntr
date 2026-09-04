#!/bin/bash
# Hysteria2 salamander obfs 交叉验证:NTR hy2(obfs=salamander)<-> sing-box / mihomo。
# NTR 底层 metacubex/sing-quic 支持 SalamanderPassword,接线 hy2 Options.Obfs;禁改线格式。
# xray 无 hy2,故对 sing-box/mihomo 验证。
#   A: NTR hy2 客户端(salamander)→ 对端 hy2 服务端
#   B: 对端 hy2 客户端 → NTR hy2 服务端
set -u
NET=ix-hy2s; PFX=ixhy2s-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; PW="hy2pass"; OBFS="salamander-secret-42"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
docker run --rm -v $D:/out alpine sh -c "apk add -q openssl >/dev/null 2>&1; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout /out/_hy2s_key.pem -out /out/_hy2s_cert.pem -days 3650 -nodes -subj '/CN=example.com' >/dev/null 2>&1"
sleep 1

# ---- 服务端(hy2, obfs=salamander) ----
ntr_srv(){ cat > $D/_hy2s_nsrv.yaml <<Y
inbounds:
  - name: hy2-in
    type: hysteria2
    listen: 0.0.0.0:8443
    tls:
      cert-file: /cert.pem
      key-file: /key.pem
    obfs: "$OBFS"
    users:
      - password: "$PW"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
  docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_hy2s_nsrv.yaml:/c.yaml:ro -v $D/_hy2s_cert.pem:/cert.pem:ro -v $D/_hy2s_key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
singbox_srv(){ cat > $D/_hy2s_sbsrv.json <<J
{"log":{"level":"error"},"inbounds":[{"type":"hysteria2","listen":"::","listen_port":8443,"users":[{"password":"$PW"}],"obfs":{"type":"salamander","password":"$OBFS"},"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem"}}],"outbounds":[{"type":"direct"}]}
J
  docker run -d --name ${PFX}s --network $NET -v $D/_hy2s_sbsrv.json:/c.json:ro -v $D/_hy2s_cert.pem:/cert.pem:ro -v $D/_hy2s_key.pem:/key.pem:ro ghcr.io/sagernet/sing-box:latest run -c /c.json >/dev/null 2>&1; }
mihomo_srv(){ cat > $D/_hy2s_msrv.yaml <<Y
mixed-port: 7890
log-level: warning
listeners:
  - {name: hy2in, type: hysteria2, listen: 0.0.0.0, port: 8443, users: {u: "$PW"}, obfs: salamander, obfs-password: "$OBFS", certificate: /root/.config/mihomo/cert.pem, private-key: /root/.config/mihomo/key.pem}
Y
  # mihomo SAFE_PATHS 限证书须在 config 目录内
  docker run -d --name ${PFX}s --network $NET -v $D/_hy2s_msrv.yaml:/root/.config/mihomo/config.yaml:ro -v $D/_hy2s_cert.pem:/root/.config/mihomo/cert.pem:ro -v $D/_hy2s_key.pem:/root/.config/mihomo/key.pem:ro metacubex/mihomo:latest >/dev/null 2>&1; }

# ---- 客户端(socks 1080 → hy2 出站)----
ntr_cli(){ cat > $D/_hy2s_ncli.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: hysteria2
    server: "${PFX}s:8443"
    secret: "$PW"
    sni: example.com
    insecure: true
    obfs: "$OBFS"
Y
  docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_hy2s_ncli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
singbox_cli(){ cat > $D/_hy2s_sbcli.json <<J
{"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"hysteria2","server":"${PFX}s","server_port":8443,"password":"$PW","obfs":{"type":"salamander","password":"$OBFS"},"tls":{"enabled":true,"server_name":"example.com","insecure":true}}]}
J
  docker run -d --name ${PFX}c --network $NET -v $D/_hy2s_sbcli.json:/c.json:ro ghcr.io/sagernet/sing-box:latest run -c /c.json >/dev/null 2>&1; }
mihomo_cli(){ cat > $D/_hy2s_mcli.yaml <<Y
mixed-port: 1080
allow-lan: true
bind-address: '*'
log-level: warning
proxies:
  - {name: p, type: hysteria2, server: ${PFX}s, port: 8443, password: "$PW", obfs: salamander, obfs-password: "$OBFS", sni: example.com, skip-cert-verify: true}
rules: ["MATCH,p"]
Y
  docker run -d --name ${PFX}c --network $NET -v $D/_hy2s_mcli.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }

runtcp(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null; }
test_dir(){ # $1=label $2=srv-fn $3=cli-fn
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
  $2; sleep 2; $3; sleep 3
  local ok=FAIL i; for i in 1 2 3 4 5; do echo "$(runtcp)" | grep -q Hostname && { ok=PASS; break; }; sleep 1; done
  printf "  [%s]  %s\n" "$1" "$ok"
  [ $ok = FAIL ] && { docker logs ${PFX}c 2>&1|tail -2|sed 's/^/    CLI:/'; docker logs ${PFX}s 2>&1|tail -2|sed 's/^/    SRV:/'; }
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1; }

test_dir "A NTRcli -> singboxSrv" singbox_srv ntr_cli
test_dir "A NTRcli -> mihomoSrv"  mihomo_srv  ntr_cli
test_dir "B singboxCli -> NTRSrv" ntr_srv singbox_cli
test_dir "B mihomoCli -> NTRSrv"  ntr_srv mihomo_cli
cleanup; echo DONE
