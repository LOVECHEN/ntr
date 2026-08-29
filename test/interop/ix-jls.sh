#!/bin/bash
# JLS(REALITY 式抗检测 TLS 变体)交叉验证:NTR [jls,vless] <-> mihomo(vless + jls-opts/jls-config)。
# JLS 线格式全在 github.com/metacubex/jls-tls(NTR 与 mihomo 同源),对认证通过的对端逐字节一致。
# xray/sing-box 无 JLS,故仅 mihomo 可验(+ NTR↔NTR 自环)。
set -u
NET=ix-jls; PFX=ixjls-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; UUID="11111111-1111-1111-1111-111111111111"
U=jlsuser; PW=jlspass
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1; sleep 1
run_ntr(){ docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_mi(){ docker run -d --name $1 --network $NET -v $2:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }
pull(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://$1:1080 http://${PFX}target/ 2>&1; }
ntr_srv(){ cat > $1 <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: jls, username: $U, password: $PW, dest: "example.com:443"}, {type: vless}]
    users: [{uuid: "$UUID"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
}
ntr_cli(){ cat > $1 <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - {name: up, type: proxy, server: "$2:10000", secret: "$UUID", layers: [{type: jls, username: $U, password: $PW, sni: example.com}, {type: vless}]}
Y
}
mi_cli(){ cat > $1 <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - {name: p, type: vless, server: $2, port: 10000, uuid: $UUID, network: tcp, tls: true, servername: example.com, skip-cert-verify: true, jls-opts: {username: $U, password: $PW}}
rules: ["MATCH,p"]
Y
}
mi_srv(){ cat > $1 <<Y
log-level: warning
listeners:
  - name: vless-in
    type: vless
    listen: 0.0.0.0
    port: 10000
    users: [{username: u, uuid: $UUID}]
    jls-config: {enable: true, users: [{username: $U, password: $PW}], dest: "example.com:443"}
Y
}
chk(){ echo "$1" | grep -q Hostname && echo PASS || echo FAIL; }

# A. mihomo vless+jls 客户端 → NTR [jls,vless] 服务端
docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
ntr_srv $D/_jA_s.yaml; run_ntr ${PFX}s $D/_jA_s.yaml; sleep 2
mi_cli $D/_jA_c.yaml ${PFX}s; run_mi ${PFX}c $D/_jA_c.yaml; sleep 4
echo "  [A. mihomo vless+jls → NTR [jls,vless] 服务端]  $(chk "$(pull ${PFX}c)")"

# B. NTR [jls,vless] 客户端 → mihomo vless+jls-config 服务端
docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
mi_srv $D/_jB_s.yaml; run_mi ${PFX}s $D/_jB_s.yaml; sleep 3
ntr_cli $D/_jB_c.yaml ${PFX}s; run_ntr ${PFX}c $D/_jB_c.yaml; sleep 2
echo "  [B. NTR [jls,vless] → mihomo vless+jls-config 服务端]  $(chk "$(pull ${PFX}c)")"

# C. NTR↔NTR 自环
docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
ntr_srv $D/_jC_s.yaml; run_ntr ${PFX}s $D/_jC_s.yaml; sleep 2
ntr_cli $D/_jC_c.yaml ${PFX}s; run_ntr ${PFX}c $D/_jC_c.yaml; sleep 2
echo "  [C. NTR [jls,vless] 客户端 → NTR 服务端(自环)]  $(chk "$(pull ${PFX}c)")"
cleanup; echo DONE
