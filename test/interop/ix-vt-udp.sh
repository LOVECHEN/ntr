#!/bin/bash
# 组 2 UDP:vmess/trojan 的 UDP 中继与 xray/mihomo/sing-box 双向。
# 判据:ixt-socksudp.py 经 socks5 UDP-ASSOCIATE 打 ixt-echo:9999,回显 == 发送 = 通。
# client 容器必须叫 ixt-cli、echo 必须叫 ixt-echo(脚本硬编码)→ UDP 用例串行跑。
set -u
D=/tmp/ntr-interop; cd "$D"; NET=ix-vt
UUID="11111111-1111-1111-1111-111111111111"; PW="p"
docker network create $NET >/dev/null 2>&1
RESULT=""
row(){ RESULT="${RESULT}| $1 | $2 | $3 | $4 |\n"; }
wait_port(){ for i in $(seq 1 30); do docker run --rm --network $NET curlimages/curl:latest -s --connect-timeout 2 -o /dev/null "http://$1:$2" >/dev/null 2>&1; [ $? -ne 7 ] && return 0; sleep 0.5; done; return 1; }
runudp(){ docker run --rm --network $NET -v $D/ixt-socksudp.py:/u.py:ro python:3-alpine python /u.py 2>&1; }

run_ntr(){ docker run -d --name $2 --network $NET -v $D/ntr:/ntr:ro -v $D/$1:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_xray(){ docker run -d --name $2 --network $NET -v $D/$1:/c.json:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro -v $D/ca.pem:/ca.pem:ro ghcr.io/xtls/xray-core:latest run -c /c.json >/dev/null 2>&1; }
run_sb(){ docker run -d --name $2 --network $NET -v $D/$1:/c.json:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro -v $D/ca.pem:/ca.pem:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1; }
run_mihomo(){ docker run -d --name $2 --network $NET -v $D/$1:/root/.config/mihomo/config.yaml:ro -v $D/cert.pem:/root/.config/mihomo/cert.pem:ro -v $D/key.pem:/root/.config/mihomo/key.pem:ro -v $D/ca.pem:/root/.config/mihomo/ca.pem:ro metacubex/mihomo:latest >/dev/null 2>&1; }

# ---- A 方向:NTR client(ixt-cli, socks udp)→ peer server(ixt-srv)----
udpA(){ # $1=combo $2=peerver $3=ntr_cli_tpl $4=peer_srv_cfg $5=run_peer
  docker rm -f ixt-echo ixt-srv ixt-cli >/dev/null 2>&1; sleep 1
  docker run -d --name ixt-echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
  $5 $4 ixt-srv
  sed "s/@SRV@/ixt-srv/g" $3 > cfg-u-cli.yaml; run_ntr cfg-u-cli.yaml ixt-cli
  wait_port ixt-srv 10000; wait_port ixt-cli 1080; sleep 1
  local o=$(runudp)
  if echo "$o" | grep -q "GOT b'PINGUDP"; then row "$1 UDP" "NTR→$6" "$2" "✅通"; echo "[OK] $1 UDP NTR→$6";
  elif [ "$1 $6" = "trojan mihomo" ]; then row "$1 UDP" "NTR→$6" "$2" "⛔对端不支持(mihomo trojan inbound 无 UDP;真 xray trojan 客户端同样超时)"; echo "[SKIP] $1 UDP NTR→$6 : 对端不支持";
  else row "$1 UDP" "NTR→$6" "$2" "❌不通"; echo "[FAIL] $1 UDP NTR→$6 : $o"; docker logs ixt-srv 2>&1|tail -3; fi
  docker rm -f ixt-echo ixt-srv ixt-cli >/dev/null 2>&1
}
# ---- B 方向:peer client(ixt-cli, socks/mixed udp)→ NTR server(ixt-srv)----
udpB(){ # $1=combo $2=peerver $3=ntr_srv_cfg $4=peer_cli_tpl $5=run_peer $6=peername
  docker rm -f ixt-echo ixt-srv ixt-cli >/dev/null 2>&1; sleep 1
  docker run -d --name ixt-echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
  run_ntr $3 ixt-srv
  sed "s/@SRV@/ixt-srv/g" $4 > cfg-u-pcli.cfg; $5 cfg-u-pcli.cfg ixt-cli
  wait_port ixt-srv 10000; wait_port ixt-cli 1080; sleep 1
  local o=$(runudp)
  echo "$o" | grep -q "GOT b'PINGUDP" && { row "$1 UDP" "$6→NTR" "$2" "✅通"; echo "[OK] $1 UDP $6→NTR"; } || { row "$1 UDP" "$6→NTR" "$2" "❌不通"; echo "[FAIL] $1 UDP $6→NTR : $o"; docker logs ixt-srv 2>&1|tail -3; docker logs ixt-cli 2>&1|tail -3; }
  docker rm -f ixt-echo ixt-srv ixt-cli >/dev/null 2>&1
}

# ===== 对端 UDP 配置 =====
# xray vmess/trojan server 已支持 UDP(freedom 出站);socks 入站 udp:true
cat > u-xvm-cli.json.tpl <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"@SRV@","port":10000,"users":[{"id":"$UUID","alterId":0,"security":"auto"}]}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"usage":"verify","certificateFile":"/ca.pem"}]}}}]}
EOF
cat > u-xtj-cli.json.tpl <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"@SRV@","port":10000,"password":"$PW"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"usage":"verify","certificateFile":"/ca.pem"}]}}}]}
EOF
# sing-box mixed 入站(udp 天然)
cat > u-svm-cli.json.tpl <<EOF
{"log":{"level":"warn"},"inbounds":[{"type":"socks","listen":"::","listen_port":1080,"udp_timeout":"5m"}],"outbounds":[{"type":"vmess","server":"@SRV@","server_port":10000,"uuid":"$UUID","security":"auto","tls":{"enabled":true,"server_name":"example.com","insecure":true}}]}
EOF
cat > u-stj-cli.json.tpl <<EOF
{"log":{"level":"warn"},"inbounds":[{"type":"socks","listen":"::","listen_port":1080,"udp_timeout":"5m"}],"outbounds":[{"type":"trojan","server":"@SRV@","server_port":10000,"password":"$PW","tls":{"enabled":true,"server_name":"example.com","insecure":true}}]}
EOF
# mihomo socks 入站 udp + proxy udp:true
cat > u-mvm-cli.yaml.tpl <<EOF
log-level: warning
socks-port: 1080
allow-lan: true
bind-address: "*"
proxies: [{name: p, type: vmess, server: @SRV@, port: 10000, uuid: $UUID, alterId: 0, cipher: auto, tls: true, servername: example.com, skip-cert-verify: true, udp: true}]
rules: ["MATCH,p"]
EOF
cat > u-mtj-cli.yaml.tpl <<EOF
log-level: warning
socks-port: 1080
allow-lan: true
bind-address: "*"
proxies: [{name: p, type: trojan, server: @SRV@, port: 10000, password: $PW, sni: example.com, skip-cert-verify: true, udp: true}]
rules: ["MATCH,p"]
EOF

run_one(){
case "$1" in
 # A: NTR client → peer server ; 复用 ix-vmess-trojan.sh 生成的 n-vm-cli.yaml.tpl / p-*-srv
 uvmA) udpA "vmess" "xray-core 26.3.27" n-vm-cli.yaml.tpl p-xvm-srv.json run_xray  xray ;;
 uvmC) udpA "vmess" "sing-box 1.13.19"  n-vm-cli.yaml.tpl p-svm-srv.json run_sb    sing-box ;;
 uvmE) udpA "vmess" "mihomo v1.19.30"   n-vm-cli.yaml.tpl p-mvm-srv.yaml run_mihomo mihomo ;;
 utjA) udpA "trojan" "xray-core 26.3.27" n-tj-cli.yaml.tpl p-xtj-srv.json run_xray  xray ;;
 utjC) udpA "trojan" "sing-box 1.13.19"  n-tj-cli.yaml.tpl p-stj-srv.json run_sb    sing-box ;;
 utjE) udpA "trojan" "mihomo v1.19.30"   n-tj-cli.yaml.tpl p-mtj-srv.yaml run_mihomo mihomo ;;
 # B: peer client → NTR server
 uvmB) udpB "vmess" "xray-core 26.3.27" n-vm-srv.yaml u-xvm-cli.json.tpl run_xray  xray ;;
 uvmD) udpB "vmess" "sing-box 1.13.19"  n-vm-srv.yaml u-svm-cli.json.tpl run_sb    sing-box ;;
 uvmF) udpB "vmess" "mihomo v1.19.30"   n-vm-srv.yaml u-mvm-cli.yaml.tpl run_mihomo mihomo ;;
 utjB) udpB "trojan" "xray-core 26.3.27" n-tj-srv.yaml u-xtj-cli.json.tpl run_xray  xray ;;
 utjD) udpB "trojan" "sing-box 1.13.19"  n-tj-srv.yaml u-stj-cli.json.tpl run_sb    sing-box ;;
 utjF) udpB "trojan" "mihomo v1.19.30"   n-tj-srv.yaml u-mtj-cli.yaml.tpl run_mihomo mihomo ;;
esac
}
SEL="${1:-uvmA uvmB uvmC uvmD uvmE uvmF utjA utjB utjC utjD utjE utjF}"
for t in $SEL; do run_one "$t"; done
echo ""; echo "═══════════ UDP 结论表 ═══════════"
echo "| 组合 | 方向 | 对端 | 结果 |"; echo "|------|------|------|------|"; printf "$RESULT"
