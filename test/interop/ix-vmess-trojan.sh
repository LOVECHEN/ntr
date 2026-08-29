#!/bin/bash
# 组 2:VMess(AEAD) + Trojan 与 xray / mihomo / sing-box 的双向互通回归。
# 铁律:禁止修改协议线格式。失败先查测试配置,线格式不符才改 NTR 匹配真实现。
# 专属 docker network: ix-vt ;容器名前缀: ixt-
# 每个方向用【独立容器名后缀】避免快速复用同名导致 docker 内嵌 DNS 记录陈旧(会把
# 代理链打断、curl 请求泄漏到宿主 Surge 返回错误页 → 假阴性)。
set -u
D=/tmp/ntr-interop; cd "$D"
NET=ix-vt
UUID="11111111-1111-1111-1111-111111111111"
PW="p"

docker network create $NET >/dev/null 2>&1

RESULT=""
row(){ RESULT="${RESULT}| $1 | $2 | $3 | $4 |\n"; }

# 等容器端口就绪(最多 ~15s):curl TCP 连接检测。exit 7 = 连不上;其它(含协议错)= 端口已开
wait_port(){ # $1=host $2=port
  for i in $(seq 1 30); do
    docker run --rm --network $NET curlimages/curl:latest -s --connect-timeout 2 -o /dev/null "http://$1:$2" >/dev/null 2>&1
    [ $? -ne 7 ] && return 0
    sleep 0.5
  done
  return 1
}

# 判据:经 socks5h 代理($1:1080)打靶机 $2,拿到 Hostname 行=通
probe(){ local out ok=0
  for i in 1 2 3; do
    out=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x socks5h://$1:1080 http://$2/ 2>&1)
    echo "$out" | grep -q Hostname && { ok=1; break; }; sleep 1.5
  done
  [ $ok -eq 1 ] && return 0 || { LASTERR=$(echo "$out" | head -c 200); return 1; }
}
probe_http(){ local out ok=0
  for i in 1 2 3; do
    out=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x http://$1:1080 http://$2/ 2>&1)
    echo "$out" | grep -q Hostname && { ok=1; break; }; sleep 1.5
  done
  [ $ok -eq 1 ] && return 0 || { LASTERR=$(echo "$out" | head -c 200); return 1; }
}

# ---- 启动器(S=后缀,保证唯一)----
run_ntr(){ docker run -d --name $2 --network $NET -v $D/ntr:/ntr:ro -v $D/$1:/c.yaml:ro \
    -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_xray(){ docker run -d --name $2 --network $NET -v $D/$1:/c.json:ro -v $D/cert.pem:/cert.pem:ro \
    -v $D/key.pem:/key.pem:ro -v $D/ca.pem:/ca.pem:ro ghcr.io/xtls/xray-core:latest run -c /c.json >/dev/null 2>&1; }
run_sb(){ docker run -d --name $2 --network $NET -v $D/$1:/c.json:ro -v $D/cert.pem:/cert.pem:ro \
    -v $D/key.pem:/key.pem:ro -v $D/ca.pem:/ca.pem:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1; }
run_mihomo(){ docker run -d --name $2 --network $NET \
    -v $D/$1:/root/.config/mihomo/config.yaml:ro \
    -v $D/cert.pem:/root/.config/mihomo/cert.pem:ro \
    -v $D/key.pem:/root/.config/mihomo/key.pem:ro \
    -v $D/ca.pem:/root/.config/mihomo/ca.pem:ro metacubex/mihomo:latest >/dev/null 2>&1; }

# 一个方向 = 独立命名空间。SUF=方向标识;SRV/CLI/PEER/TGT 都带 SUF。
# gen_* 函数把 <SRV><TGT> 占位替换成真名后写 config。
mk(){ printf '%s' "$1" | sed "s/@SRV@/$2/g; s/@TGT@/$3/g"; }

# ============ 单方向执行器 ============
# A 方向:NTR client → peer server。CLI=NTR(socks 1080), PEER=对端服务端(10000)
# B 方向:peer client → NTR server。SRV=NTR(10000), CLI=对端客户端(1080/http)
dirA(){ # $1=label $2=combo $3=peername $4=peerver $5=ntrcli_cfg $6=peer_srv_cfg $7=run_peer_fn $8=probefn
  local S=$2$3; S=${S//+/}; S=${S//→/_}
  local TGT=ixt-tgt-$S PEER=ixt-peer-$S CLI=ixt-cli-$S
  docker rm -f $TGT $PEER $CLI >/dev/null 2>&1
  docker run -d --name $TGT --network $NET traefik/whoami >/dev/null 2>&1
  mk "$(cat $5.tpl)" $PEER $TGT > cfg-$S-cli.yaml
  $7 $6 $PEER               # 起对端服务端(其 config 里靶机名无关,监听 10000)
  run_ntr cfg-$S-cli.yaml $CLI
  wait_port $PEER 10000; wait_port $CLI 1080; sleep 1
  if $8 $CLI $TGT; then row "$2" "$1" "$4" "✅通"; echo "[OK] $1 $2"; else row "$2" "$1" "$4" "❌不通"; echo "[FAIL] $1 $2 : $LASTERR"; docker logs $PEER 2>&1|tail -3; docker logs $CLI 2>&1|tail -3; fi
  docker rm -f $TGT $PEER $CLI >/dev/null 2>&1
}
dirB(){ # $1=label $2=combo $3=peername $4=peerver $5=ntrsrv_cfg $6=peer_cli_cfg $7=run_peer_fn $8=probefn
  local S=$2$3; S=${S//+/}; S=${S//→/_}
  local TGT=ixt-tgt-$S SRV=ixt-srv-$S CLI=ixt-cli-$S
  docker rm -f $TGT $SRV $CLI >/dev/null 2>&1
  docker run -d --name $TGT --network $NET traefik/whoami >/dev/null 2>&1
  run_ntr $5 $SRV
  mk "$(cat $6.tpl)" $SRV $TGT > cfg-$S-cli.cfg
  $7 cfg-$S-cli.cfg $CLI
  wait_port $SRV 10000; wait_port $CLI 1080; sleep 1
  if $8 $CLI $TGT; then row "$2" "$1" "$4" "✅通"; echo "[OK] $1 $2"; else row "$2" "$1" "$4" "❌不通"; echo "[FAIL] $1 $2 : $LASTERR"; docker logs $SRV 2>&1|tail -3; docker logs $CLI 2>&1|tail -3; fi
  docker rm -f $TGT $SRV $CLI >/dev/null 2>&1
}

###############################################################################
# 配置模板(@SRV@=NTR/对端服务端容器名, @TGT@=靶机名)
###############################################################################
# ---- NTR 服务端(固定,不含占位)----
cat > n-vm-srv.yaml <<EOF
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: tls, cert-file: /cert.pem, key-file: /key.pem}, {type: vmess, uuid: "$UUID"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
EOF
cat > n-tj-srv.yaml <<EOF
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: tls, cert-file: /cert.pem, key-file: /key.pem}, {type: trojan}]
    users: [{password: "$PW"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
EOF
# ---- NTR 客户端模板 ----
cat > n-vm-cli.yaml.tpl <<EOF
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - {name: up, type: proxy, server: "@SRV@:10000", layers: [{type: tls, sni: example.com, insecure: true}, {type: vmess, uuid: "$UUID"}]}
EOF
cat > n-tj-cli.yaml.tpl <<EOF
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - {name: up, type: proxy, server: "@SRV@:10000", secret: "$PW", layers: [{type: tls, sni: example.com, insecure: true}, {type: trojan}]}
EOF

# ---- xray 服务端(不含占位:监听 10000,freedom 出站)----
cat > p-xvm-srv.json <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"vmess","settings":{"clients":[{"id":"$UUID","alterId":0}]},"streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/cert.pem","keyFile":"/key.pem"}]}}}],"outbounds":[{"protocol":"freedom"}]}
EOF
cat > p-xtj-srv.json <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"trojan","settings":{"clients":[{"password":"$PW"}]},"streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/cert.pem","keyFile":"/key.pem"}]}}}],"outbounds":[{"protocol":"freedom"}]}
EOF
# ---- xray 客户端模板(26.x 删了 allowInsecure → 用 CA verify)----
cat > p-xvm-cli.json.tpl <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"@SRV@","port":10000,"users":[{"id":"$UUID","alterId":0,"security":"auto"}]}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"usage":"verify","certificateFile":"/ca.pem"}]}}}]}
EOF
cat > p-xtj-cli.json.tpl <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"@SRV@","port":10000,"password":"$PW"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"usage":"verify","certificateFile":"/ca.pem"}]}}}]}
EOF

# ---- sing-box 服务端 ----
cat > p-svm-srv.json <<EOF
{"log":{"level":"warn"},"inbounds":[{"type":"vmess","listen":"::","listen_port":10000,"users":[{"uuid":"$UUID"}],"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem"}}],"outbounds":[{"type":"direct"}]}
EOF
cat > p-stj-srv.json <<EOF
{"log":{"level":"warn"},"inbounds":[{"type":"trojan","listen":"::","listen_port":10000,"users":[{"password":"$PW"}],"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem"}}],"outbounds":[{"type":"direct"}]}
EOF
# ---- sing-box 客户端模板 ----
cat > p-svm-cli.json.tpl <<EOF
{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"vmess","server":"@SRV@","server_port":10000,"uuid":"$UUID","security":"auto","tls":{"enabled":true,"server_name":"example.com","insecure":true}}]}
EOF
cat > p-stj-cli.json.tpl <<EOF
{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"trojan","server":"@SRV@","server_port":10000,"password":"$PW","tls":{"enabled":true,"server_name":"example.com","insecure":true}}]}
EOF

# ---- mihomo 服务端(vmess/trojan inbound listener + TLS)----
cat > p-mvm-srv.yaml <<EOF
log-level: warning
listeners:
  - name: in
    type: vmess
    listen: 0.0.0.0
    port: 10000
    users: [{username: u, uuid: $UUID, alterId: 0}]
    certificate: /root/.config/mihomo/cert.pem
    private-key: /root/.config/mihomo/key.pem
EOF
cat > p-mtj-srv.yaml <<EOF
log-level: warning
listeners:
  - name: in
    type: trojan
    listen: 0.0.0.0
    port: 10000
    users: [{username: u, password: $PW}]
    certificate: /root/.config/mihomo/cert.pem
    private-key: /root/.config/mihomo/key.pem
EOF
# ---- mihomo 客户端模板 ----
cat > p-mvm-cli.yaml.tpl <<EOF
log-level: warning
mixed-port: 1080
allow-lan: true
bind-address: "*"
proxies: [{name: p, type: vmess, server: @SRV@, port: 10000, uuid: $UUID, alterId: 0, cipher: auto, tls: true, servername: example.com, skip-cert-verify: true}]
rules: ["MATCH,p"]
EOF
cat > p-mtj-cli.yaml.tpl <<EOF
log-level: warning
mixed-port: 1080
allow-lan: true
bind-address: "*"
proxies: [{name: p, type: trojan, server: @SRV@, port: 10000, password: $PW, sni: example.com, skip-cert-verify: true}]
rules: ["MATCH,p"]
EOF

###############################################################################
run_one(){
case "$1" in
 vmA) dirA "NTR→xray"     "vmess+tls" xray "xray-core 26.3.27" n-vm-cli.yaml p-xvm-srv.json run_xray  probe ;;
 vmB) dirB "xray→NTR"     "vmess+tls" xray "xray-core 26.3.27" n-vm-srv.yaml p-xvm-cli.json run_xray  probe ;;
 vmC) dirA "NTR→sing-box" "vmess+tls" sb   "sing-box 1.13.19"   n-vm-cli.yaml p-svm-srv.json run_sb    probe ;;
 vmD) dirB "sing-box→NTR" "vmess+tls" sb   "sing-box 1.13.19"   n-vm-srv.yaml p-svm-cli.json run_sb    probe_http ;;
 vmE) dirA "NTR→mihomo"   "vmess+tls" mh   "mihomo v1.19.30"     n-vm-cli.yaml p-mvm-srv.yaml run_mihomo probe ;;
 vmF) dirB "mihomo→NTR"   "vmess+tls" mh   "mihomo v1.19.30"     n-vm-srv.yaml p-mvm-cli.yaml run_mihomo probe_http ;;
 tjA) dirA "NTR→xray"     "trojan+tls" xray "xray-core 26.3.27" n-tj-cli.yaml p-xtj-srv.json run_xray  probe ;;
 tjB) dirB "xray→NTR"     "trojan+tls" xray "xray-core 26.3.27" n-tj-srv.yaml p-xtj-cli.json run_xray  probe ;;
 tjC) dirA "NTR→sing-box" "trojan+tls" sb   "sing-box 1.13.19"   n-tj-cli.yaml p-stj-srv.json run_sb    probe ;;
 tjD) dirB "sing-box→NTR" "trojan+tls" sb   "sing-box 1.13.19"   n-tj-srv.yaml p-stj-cli.json run_sb    probe_http ;;
 tjE) dirA "NTR→mihomo"   "trojan+tls" mh   "mihomo v1.19.30"     n-tj-cli.yaml p-mtj-srv.yaml run_mihomo probe ;;
 tjF) dirB "mihomo→NTR"   "trojan+tls" mh   "mihomo v1.19.30"     n-tj-srv.yaml p-mtj-cli.yaml run_mihomo probe_http ;;
esac
}

SEL="${1:-vmA vmB vmC vmD vmE vmF tjA tjB tjC tjD tjE tjF}"
for t in $SEL; do run_one "$t"; done

echo ""
echo "═══════════ TCP 结论表 ═══════════"
echo "| 组合 | 方向 | 对端 | 结果 |"
echo "|------|------|------|------|"
printf "$RESULT"

# ── UDP 回归(vmess/trojan 的 UDP-over-stream)。UDP 用例硬编码容器名 ixt-cli/ixt-echo,串行跑 ──
# 依赖本脚本上面生成的模板(n-*-cli.yaml.tpl / n-*-srv.yaml / p-*-srv.*)。
if [ "${2:-udp}" = "udp" ]; then
  echo ""; echo "▶ 运行 UDP 回归 (ix-vt-udp.sh) ..."
  bash "$D/ix-vt-udp.sh"
fi
