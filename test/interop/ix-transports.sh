#!/bin/bash
# 组4:传输层 ws / grpc / httpupgrade 双向互通回归(承载协议 vless,叠 TLS)
# 对端:xray-core / mihomo / sing-box。铁律:禁止修改协议线格式。
# 专属 network=ix-tr,容器名前缀=ixr-。
set -u
D=/tmp/ntr-interop; cd $D
NET=ix-tr
UUID="11111111-1111-1111-1111-111111111111"

cleanup(){ docker rm -f $(docker ps -aq --filter "name=ixr-") >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
cleanup
docker network create $NET >/dev/null 2>&1

hit(){ echo "$1" | grep -q Hostname && echo "PASS | $2" || { echo "FAIL | $2"; [ -n "${3:-}" ] && echo "      last: $(echo "$1" | tr '\n' ' ' | head -c 200)"; }; }

# 起靶机
docker run -d --name ixr-target --network $NET traefik/whoami >/dev/null

# 探测重试:CI 冷 runner 上对端(xray/mihomo/sing-box)服务端起得慢,固定 sleep 常不够;
# 重试至拿到 Hostname(成功)或耗尽——成功即早退(过的用例零额外开销),只有真失败才付满重试。
curlp(){ local i out; for i in 1 2 3 4 5 6; do out=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 "$@" 2>&1); echo "$out" | grep -q Hostname && { echo "$out"; return; }; sleep 1; done; echo "$out"; }

# ============================================================
# 通用:NTR 服务端/客户端配置(TLS+transport+vless)
# transport: ws / grpc / httpupgrade
# ============================================================
ntr_srv(){ # $1=transport-layer-yaml
  cat > ixr-ntrsrv.yaml <<EOF
inbounds:
  - listen: 0.0.0.0:10000
    layers:
$1
      - {type: vless}
    users: [{uuid: "$UUID"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
EOF
}
ntr_cli(){ # $1=server host, $2=transport-layer-yaml
  cat > ixr-ntrcli.yaml <<EOF
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - name: up
    type: proxy
    server: "$1:10000"
    secret: "$UUID"
    layers:
$2
      - {type: vless}
EOF
}
run_ntr_srv(){ docker run -d --name ixr-ntrsrv --network $NET -v $D/ntr:/ntr:ro -v $D/ixr-ntrsrv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_ntr_cli(){ docker run -d --name ixr-ntrcli --network $NET -v $D/ntr:/ntr:ro -v $D/ixr-ntrcli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }

# transport-layer 片段(server 侧 tls 带证书;client 侧 tls insecure）
# ws
NTR_WS_S='      - {type: tls, cert-file: /cert.pem, key-file: /key.pem}
      - {type: ws, path: /ws, host: example.com}'
NTR_WS_C='      - {type: tls, sni: example.com, insecure: true}
      - {type: ws, path: /ws, host: example.com}'
# grpc(需 h2 alpn)
NTR_GRPC_S='      - {type: tls, cert-file: /cert.pem, key-file: /key.pem, alpn: h2}
      - {type: grpc, service-name: GunService}'
NTR_GRPC_C='      - {type: tls, sni: example.com, insecure: true, alpn: h2}
      - {type: grpc, service-name: GunService}'
# httpupgrade
NTR_HU_S='      - {type: tls, cert-file: /cert.pem, key-file: /key.pem}
      - {type: httpupgrade, path: /up, host: example.com}'
NTR_HU_C='      - {type: tls, sni: example.com, insecure: true}
      - {type: httpupgrade, path: /up, host: example.com}'

del(){ docker rm -f ixr-ntrsrv ixr-ntrcli ixr-peer >/dev/null 2>&1; }

# ============================================================
# xray 配置片段(streamSettings)
# ============================================================
xray_stream(){ # $1=transport json
  echo "$1"
}
# xray server(vless inbound)
run_xray_srv(){ # $1=stream json
  cat > ixr-xsrv.json <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"vless","settings":{"clients":[{"id":"$UUID"}],"decryption":"none"},"streamSettings":$1}],"outbounds":[{"protocol":"freedom"}]}
EOF
  docker run -d --name ixr-peer --network $NET -v $D/ixr-xsrv.json:/c.json:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro ghcr.io/xtls/xray-core:latest -c /c.json >/dev/null 2>&1
}
run_xray_cli(){ # $1=stream json, $2=server host
  cat > ixr-xcli.json <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"$2","port":10000,"users":[{"id":"$UUID","encryption":"none"}]}]},"streamSettings":$1}]}
EOF
  docker run -d --name ixr-peer --network $NET -v $D/ixr-xcli.json:/c.json:ro -v $D/ca.pem:/ca.pem:ro ghcr.io/xtls/xray-core:latest -c /c.json >/dev/null 2>&1
}

# ============================================================
# 执行一个组合
# args: label transport
# ============================================================

echo "########## 组4:传输层 ws/grpc/httpupgrade × vless × TLS ##########"

# ---------------- xray ----------------
run_xray_case(){ # $1=transport name, $2=ntr_srv_layer, $3=ntr_cli_layer, $4=xray_stream_json_srv, $5=xray_stream_json_cli
  # A: NTR client -> xray server
  del; run_xray_srv "$4"; ntr_cli ixr-peer "$3"; run_ntr_cli; sleep 5
  hit "$(curlp -x socks5h://ixr-ntrcli:1080 http://ixr-target/)" "[$1] xray-core NTR->xray (A)" v
  # B: xray client -> NTR server
  del; ntr_srv "$2"; run_ntr_srv; sleep 2; run_xray_cli "$5" ixr-ntrsrv; sleep 4
  hit "$(curlp -x socks5h://ixr-peer:1080 http://ixr-target/)" "[$1] xray-core xray->NTR (B)" v
  del
}

WS_XS='{"network":"ws","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/cert.pem","keyFile":"/key.pem"}]},"wsSettings":{"path":"/ws","host":"example.com"}}'
WS_XC='{"network":"ws","security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"usage":"verify","certificateFile":"/ca.pem"}]},"wsSettings":{"path":"/ws","host":"example.com"}}'
GRPC_XS='{"network":"grpc","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/cert.pem","keyFile":"/key.pem"}],"alpn":["h2"]},"grpcSettings":{"serviceName":"GunService"}}'
GRPC_XC='{"network":"grpc","security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"usage":"verify","certificateFile":"/ca.pem"}],"alpn":["h2"]},"grpcSettings":{"serviceName":"GunService"}}'
HU_XS='{"network":"httpupgrade","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/cert.pem","keyFile":"/key.pem"}]},"httpupgradeSettings":{"path":"/up","host":"example.com"}}'
HU_XC='{"network":"httpupgrade","security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"usage":"verify","certificateFile":"/ca.pem"}]},"httpupgradeSettings":{"path":"/up","host":"example.com"}}'

run_xray_case ws       "$NTR_WS_S"   "$NTR_WS_C"   "$WS_XS"   "$WS_XC"
run_xray_case grpc     "$NTR_GRPC_S" "$NTR_GRPC_C" "$GRPC_XS" "$GRPC_XC"
run_xray_case httpupgrade "$NTR_HU_S" "$NTR_HU_C"  "$HU_XS"   "$HU_XC"

# ---------------- mihomo ----------------
run_mihomo_srv(){ # $1=full config yaml content already written to ixr-msrv.yaml
  docker run -d --name ixr-peer --network $NET -v $D/ixr-msrv.yaml:/root/.config/mihomo/config.yaml:ro -v $D/cert.pem:/root/.config/mihomo/cert.pem:ro -v $D/key.pem:/root/.config/mihomo/key.pem:ro metacubex/mihomo:latest >/dev/null 2>&1
}
run_mihomo_cli(){
  docker run -d --name ixr-peer --network $NET -v $D/ixr-mcli.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
}

mihomo_case(){ # $1=name $2=ntr_srv_layer $3=ntr_cli_layer $4=mcli_proxy_block $5=msrv_listener_block
  # A: NTR client -> mihomo server
  del
  cat > ixr-msrv.yaml <<EOF
log-level: warning
mode: direct
listeners:
$5
EOF
  run_mihomo_srv; ntr_cli ixr-peer "$3"; run_ntr_cli; sleep 6
  hit "$(curlp -x socks5h://ixr-ntrcli:1080 http://ixr-target/)" "[$1] mihomo NTR->mihomo (A)" v
  # B: mihomo client -> NTR server
  del; ntr_srv "$2"; run_ntr_srv; sleep 2
  cat > ixr-mcli.yaml <<EOF
mixed-port: 1080
allow-lan: true
bind-address: "*"
log-level: warning
proxies:
$4
rules:
  - MATCH,p
EOF
  run_mihomo_cli; sleep 5
  hit "$(curlp -x http://ixr-peer:1080 http://ixr-target/)" "[$1] mihomo mihomo->NTR (B)" v
  del
}

# mihomo client proxy blocks
M_WS_C='  - {name: p, type: vless, server: ixr-ntrsrv, port: 10000, uuid: "'$UUID'", tls: true, servername: example.com, skip-cert-verify: true, network: ws, ws-opts: {path: /ws, headers: {Host: example.com}}}'
M_GRPC_C='  - {name: p, type: vless, server: ixr-ntrsrv, port: 10000, uuid: "'$UUID'", tls: true, servername: example.com, skip-cert-verify: true, network: grpc, grpc-opts: {grpc-service-name: GunService}}'
M_HU_C='  - {name: p, type: vless, server: ixr-ntrsrv, port: 10000, uuid: "'$UUID'", tls: true, servername: example.com, skip-cert-verify: true, network: ws, ws-opts: {path: /up, v2ray-http-upgrade: true, headers: {Host: example.com}}}'

# mihomo server listener blocks
M_WS_S='  - name: in
    type: vless
    listen: 0.0.0.0
    port: 10000
    users: [{username: u, uuid: "'$UUID'"}]
    network: [ws]
    ws-path: /ws
    certificate: /root/.config/mihomo/cert.pem
    private-key: /root/.config/mihomo/key.pem'
M_GRPC_S='  - name: in
    type: vless
    listen: 0.0.0.0
    port: 10000
    users: [{username: u, uuid: "'$UUID'"}]
    network: [grpc]
    grpc-service-name: GunService
    certificate: /root/.config/mihomo/cert.pem
    private-key: /root/.config/mihomo/key.pem'
M_HU_S='  - name: in
    type: vless
    listen: 0.0.0.0
    port: 10000
    users: [{username: u, uuid: "'$UUID'"}]
    ws-path: /up
    ws-opts: {v2ray-http-upgrade: true}
    certificate: /root/.config/mihomo/cert.pem
    private-key: /root/.config/mihomo/key.pem'

mihomo_case ws          "$NTR_WS_S"   "$NTR_WS_C"   "$M_WS_C"   "$M_WS_S"
mihomo_case grpc        "$NTR_GRPC_S" "$NTR_GRPC_C" "$M_GRPC_C" "$M_GRPC_S"
mihomo_case httpupgrade "$NTR_HU_S"   "$NTR_HU_C"   "$M_HU_C"   "$M_HU_S"

# ---------------- sing-box ----------------
run_sb_srv(){ docker run -d --name ixr-peer --network $NET -v $D/ixr-sbsrv.json:/c.json:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1; }
run_sb_cli(){ docker run -d --name ixr-peer --network $NET -v $D/ixr-sbcli.json:/c.json:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1; }

sb_case(){ # $1=name $2=ntr_srv_layer $3=ntr_cli_layer $4=sb_transport_json
  # A: NTR client -> sing-box server
  del
  cat > ixr-sbsrv.json <<EOF
{"log":{"level":"warn"},"inbounds":[{"type":"vless","tag":"in","listen":"::","listen_port":10000,"users":[{"uuid":"$UUID"}],"tls":{"enabled":true,"server_name":"example.com","certificate_path":"/cert.pem","key_path":"/key.pem"},"transport":$4}],"outbounds":[{"type":"direct"}]}
EOF
  run_sb_srv; ntr_cli ixr-peer "$3"; run_ntr_cli; sleep 5
  hit "$(curlp -x socks5h://ixr-ntrcli:1080 http://ixr-target/)" "[$1] sing-box NTR->sing-box (A)" v
  # B: sing-box client -> NTR server
  del; ntr_srv "$2"; run_ntr_srv; sleep 2
  cat > ixr-sbcli.json <<EOF
{"log":{"level":"warn"},"inbounds":[{"type":"mixed","tag":"in","listen":"::","listen_port":1080}],"outbounds":[{"type":"vless","tag":"out","server":"ixr-ntrsrv","server_port":10000,"uuid":"$UUID","tls":{"enabled":true,"server_name":"example.com","insecure":true},"transport":$4}]}
EOF
  run_sb_cli; sleep 4
  hit "$(curlp -x http://ixr-peer:1080 http://ixr-target/)" "[$1] sing-box sing-box->NTR (B)" v
  del
}

SB_WS='{"type":"ws","path":"/ws","headers":{"Host":"example.com"}}'
SB_GRPC='{"type":"grpc","service_name":"GunService"}'
SB_HU='{"type":"httpupgrade","path":"/up","host":"example.com"}'

sb_case ws          "$NTR_WS_S"   "$NTR_WS_C"   "$SB_WS"
sb_case grpc        "$NTR_GRPC_S" "$NTR_GRPC_C" "$SB_GRPC"
sb_case httpupgrade "$NTR_HU_S"   "$NTR_HU_C"   "$SB_HU"

echo "########## DONE ##########"
cleanup
