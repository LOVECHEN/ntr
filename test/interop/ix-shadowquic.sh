#!/bin/bash
# ShadowQUIC(JLS-over-QUIC 抗检测代理)交叉验证:NTR <-> mihomo(唯一另一实现;xray/sing-box 无)。
# QUIC+JLS 核心桥 github.com/metacubex/jls-quic-go(NTR 与 mihomo 同源);协议帧([cmd][socks5addr])
# NTR 自写、逐字节对齐 mihomo transport/shadowquic。v1 仅 TCP CONNECT(UDP/Brutal 后续)。
set -u
NET=ix-sq; PFX=ixsq-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
U=squser; PW=sqpass
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1; sleep 1
run_ntr(){ docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_mi(){ docker run -d --name $1 --network $NET -v $2:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }
pull(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://$1:1080 http://${PFX}target/ 2>&1; }
chk(){ echo "$1" | grep -q Hostname && echo PASS || echo FAIL; }
ntr_srv(){ cat > $1 <<Y
inbounds:
  - {listen: 0.0.0.0:10000, type: shadowquic, tls: {sni: example.com}, users: [{username: $U, password: $PW}], outbound: direct}
outbounds: [{name: direct, type: direct}]
Y
}
ntr_cli(){ cat > $1 <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - {name: up, type: shadowquic, server: "$2:10000", user: $U, secret: $PW, sni: example.com}
Y
}
mi_cli(){ cat > $1 <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies: [{name: p, type: shadowquic, server: $2, port: 10000, username: $U, password: $PW, sni: example.com, alpn: [h3]}]
rules: ["MATCH,p"]
Y
}
mi_srv(){ cat > $1 <<Y
log-level: warning
listeners:
  - {name: sq-in, type: shadowquic, listen: 0.0.0.0, port: 10000, users: [{username: $U, password: $PW}], jls-upstream: {addr: "example.com:443", sni: example.com}, alpn: [h3]}
Y
}

docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
ntr_srv $D/_sqA_s.yaml; run_ntr ${PFX}s $D/_sqA_s.yaml; sleep 2
mi_cli $D/_sqA_c.yaml ${PFX}s; run_mi ${PFX}c $D/_sqA_c.yaml; sleep 4
echo "  [A. mihomo shadowquic 客户端 → NTR 服务端]  $(chk "$(pull ${PFX}c)")"

docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
mi_srv $D/_sqB_s.yaml; run_mi ${PFX}s $D/_sqB_s.yaml; sleep 3
ntr_cli $D/_sqB_c.yaml ${PFX}s; run_ntr ${PFX}c $D/_sqB_c.yaml; sleep 2
echo "  [B. NTR shadowquic 客户端 → mihomo 服务端]  $(chk "$(pull ${PFX}c)")"

docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
ntr_srv $D/_sqC_s.yaml; run_ntr ${PFX}s $D/_sqC_s.yaml; sleep 2
ntr_cli $D/_sqC_c.yaml ${PFX}s; run_ntr ${PFX}c $D/_sqC_c.yaml; sleep 2
echo "  [C. NTR shadowquic 客户端 → NTR 服务端(自环)]  $(chk "$(pull ${PFX}c)")"
cleanup; echo DONE
