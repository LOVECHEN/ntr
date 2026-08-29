#!/bin/bash
# mekya(KCP-over-HTTPS meek 轮询隧道,mihomo 独有;xray/sing-box 无)交叉验证:NTR ⇄ mihomo(vmess over mekya)。
# KCP 复用 mkcpcore(与 mihomo mkcp 线级互通);meek HTTP 轮询 + 会话多路复用 + 包捆绑 + TLS/h2 自写,逐字节对齐 mihomo。
#
# 已核对 mihomo v1.19.30 源(transport/mekya + listener/inbound/mekya.go),线格式完全一致:
#   - 请求/响应体 = KCP 包捆绑,每包 [2B BE 长度][KCP 包](bundle.go 与 mihomo 逐字节相同)。
#   - 客户端 POST,头 X-Session-ID = base64 RawURLEncoding(16B 随机);服务端 RawURLEncoding.DecodeString。
#   - 服务端 http.Server 开 HTTP1+HTTP2+UnencryptedHTTP2,over TLS 监听;不校验 path。
# ★配置要点(踩过的坑):
#   - vmess 的 uuid 必须放 vmess 层上(layers:[...,{type:vmess,uuid:X}]);放 outbound/users 会用空 uuid → bad request。
#   - mihomo mekya 客户端(A)必须设 polling-interval-initial(默认 0 空轮询打转,KCP SYN 发不出)。
#   - mihomo mekya 服务端(B)必须给 certificate/private-key(它 over-TLS 监听),且证书路径须在 SAFE_PATHS
#     (~/.config/mihomo)内;listener 段用【全块状 YAML】(mihomo yaml 库对 block 里混 flow-map 报错)。
# v1 仅 TCP CONNECT(UDP/Brutal 后续)。
set -u
NET=ix-mky; PFX=ixmky-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; UUID="11111111-1111-1111-1111-111111111111"
MC=$D/mcert.pem; MK=$D/mkey.pem
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
# 自签证书(mihomo mekya 服务端 over-TLS 监听需要;NTR 客户端 insecure:true 跳过校验)
[ -f "$MC" ] || docker run --rm -v $D:/w -w /w alpine sh -c 'apk add openssl >/dev/null 2>&1; openssl req -x509 -newkey rsa:2048 -keyout mkey.pem -out mcert.pem -days 3650 -nodes -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com" >/dev/null 2>&1'
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1; sleep 1
run_ntr(){ docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_mi(){ docker run -d --name $1 --network $NET -v $2:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }
run_mi_tls(){ docker run -d --name $1 --network $NET -v $2:/root/.config/mihomo/config.yaml:ro -v $MC:/root/.config/mihomo/mcert.pem:ro -v $MK:/root/.config/mihomo/mkey.pem:ro metacubex/mihomo:latest >/dev/null 2>&1; }
pull(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://$1:1080 http://${PFX}target/ 2>&1; }
chk(){ echo "$1" | grep -q Hostname && echo PASS || echo FAIL; }
ntr_srv(){ cat > $1 <<Y
inbounds: [{listen: 0.0.0.0:10000, layers: [{type: mekya, path: /m}, {type: vmess, uuid: "$UUID"}], outbound: direct}]
outbounds: [{name: direct, type: direct}]
Y
}
ntr_cli(){ cat > $1 <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - {name: up, type: proxy, server: "$2:10000", layers: [{type: mekya, path: /m, sni: example.com, insecure: true}, {type: vmess, uuid: "$UUID"}]}
Y
}
mi_cli(){ cat > $1 <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies: [{name: p, type: vmess, server: $2, port: 10000, uuid: $UUID, alterId: 0, cipher: auto, network: mekya, tls: true, servername: example.com, skip-cert-verify: true, mekya-opts: {url: "https://$2:10000/m", polling-interval-initial: 30, max-write-delay: 10, max-request-size: 1048576, max-write-size: 1048576, kcp: {mtu: 1350, tti: 50, uplink-capacity: 5, downlink-capacity: 20}}}]
rules: ["MATCH,p"]
Y
}
mi_srv(){ cat > $1 <<Y
log-level: warning
listeners:
  - name: vm-in
    type: vmess
    listen: 0.0.0.0
    port: 10000
    users:
      - username: u
        uuid: $UUID
        alterId: 0
    certificate: /root/.config/mihomo/mcert.pem
    private-key: /root/.config/mihomo/mkey.pem
    mekya-config:
      enable: true
      max-write-size: 10485760
      max-write-duration-ms: 500
      max-simultaneous-write-connection: 128
      packet-writing-buffer: 65536
      kcp:
        mtu: 1350
        tti: 50
        uplink-capacity: 5
        downlink-capacity: 20
Y
}

docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
ntr_srv $D/_mA_s.yaml; run_ntr ${PFX}s $D/_mA_s.yaml; sleep 2
mi_cli $D/_mA_c.yaml ${PFX}s; run_mi ${PFX}c $D/_mA_c.yaml; sleep 6
echo "  [A. mihomo vmess+mekya 客户端 → NTR 服务端]  $(chk "$(pull ${PFX}c)")"

docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
mi_srv $D/_mB_s.yaml; run_mi_tls ${PFX}s $D/_mB_s.yaml; sleep 3
ntr_cli $D/_mB_c.yaml ${PFX}s; run_ntr ${PFX}c $D/_mB_c.yaml; sleep 4
echo "  [B. NTR 客户端 → mihomo vmess+mekya 服务端]  $(chk "$(pull ${PFX}c)")"

docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
ntr_srv $D/_mC_s.yaml; run_ntr ${PFX}s $D/_mC_s.yaml; sleep 2
ntr_cli $D/_mC_c.yaml ${PFX}s; run_ntr ${PFX}c $D/_mC_c.yaml; sleep 3
echo "  [C. NTR 客户端 → NTR 服务端(自环)]  $(chk "$(pull ${PFX}c)")"
cleanup; echo DONE
