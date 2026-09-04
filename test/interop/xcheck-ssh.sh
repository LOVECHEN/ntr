#!/bin/bash
# 交叉验证:NTR ssh ↔ 真 OpenSSH / sing-box
# 专属 network=xv-ssh 容器前缀=xvs-;结束自动清理。
# 判据:经 socks5h 代理打 traefik/whoami 靶机拿到 Hostname 行 = 通。
set -u
NET=xv-ssh; P=xvs-; D=/tmp/ntr-interop; U=u; PW=pw
cleanup(){ docker rm -f ${P}target ${P}sshd ${P}ntrcli ${P}ntrsrv ${P}singbox ${P}mihomo >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
# 经 socks5h 代理探靶机,3 次重试吸收首连握手预热;命中 Hostname 打印它
probe(){ local proxy=$1 out; for i in 1 2 3; do
  out=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x "socks5h://$proxy" http://${P}target/ 2>&1)
  echo "$out" | grep -q Hostname && { echo "$out" | grep Hostname; return 0; }; sleep 2; done; echo "$out"; return 1; }
trap cleanup EXIT
cleanup
docker network create $NET >/dev/null 2>&1

# 靶机
docker run -d --name ${P}target --network $NET traefik/whoami >/dev/null

########## 方向 A:NTR ssh 客户端 → 真 OpenSSH 服务端 ##########
docker run -d --name ${P}sshd --network $NET alpine sh -c '
  apk add --no-cache openssh >/dev/null 2>&1
  ssh-keygen -A >/dev/null 2>&1
  adduser -D '"$U"' >/dev/null 2>&1; echo "'"$U:$PW"'" | chpasswd >/dev/null 2>&1
  sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config
  # Alpine 默认 sshd_config 显式 AllowTcpForwarding no,必须改成 yes(否则拒 direct-tcpip)
  sed -i "s/^AllowTcpForwarding.*/AllowTcpForwarding yes/" /etc/ssh/sshd_config
  grep -q "^AllowTcpForwarding yes" /etc/ssh/sshd_config || echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config
  /usr/sbin/sshd -D -e' >/dev/null
cat > $D/xvs-ntrcli.yaml <<EOF
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: ssh
    server: "${P}sshd:22"
    user: $U
    secret: "$PW"
EOF
# 等真 sshd 就绪且 AllowTcpForwarding 生效(apk add+keygen 在负载下可能超过固定 sleep)
for i in $(seq 1 30); do
  docker exec ${P}sshd sshd -T 2>/dev/null | grep -qi "allowtcpforwarding yes" && break
  sleep 1
done
docker run -d --name ${P}ntrcli --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/xvs-ntrcli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 4
probe ${P}ntrcli:1080 >/dev/null && echo "方向A NTR-ssh客户端 → 真OpenSSH : PASS" || { echo "方向A : FAIL"; docker logs ${P}ntrcli 2>&1|tail; }

########## NTR ssh 服务端(方向 B/C 共用) ##########
cat > $D/xvs-ntrsrv.yaml <<EOF
inbounds:
  - name: srv-in
    type: ssh
    listen: 0.0.0.0:2222
    tls:
      key-file: /hostkey
    users:
      - name: $U
        password: "$PW"
outbounds:
  - name: direct
    type: direct
EOF
docker run -d --name ${P}ntrsrv --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/xvs-ntrsrv.yaml:/c.yaml:ro -v $D/ssh_hostkey:/hostkey:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 3

########## 方向 B:真 OpenSSH 客户端(-D 动态转发)→ NTR ssh 服务端 ##########
B=$(docker run --rm --network $NET alpine sh -c '
  apk add --no-cache openssh-client sshpass curl >/dev/null 2>&1
  sshpass -p '"$PW"' ssh -N -D 0.0.0.0:1080 -p 2222 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ExitOnForwardFailure=yes '"$U"'@'"${P}"'ntrsrv &
  sleep 4; for i in 1 2 3; do curl -s --max-time 12 -x socks5h://127.0.0.1:1080 http://'"${P}"'target/ 2>&1 | grep -q Hostname && { echo OK; break; }; sleep 2; done' 2>&1)
echo "$B" | grep -q OK && echo "方向B 真OpenSSH客户端(-D) → NTR-ssh服务端 : PASS" || echo "方向B : FAIL"

########## 方向 C:sing-box ssh 出站 → NTR ssh 服务端 ##########
cat > $D/xvs-singbox.json <<EOF
{"log":{"level":"error"},
 "inbounds":[{"type":"mixed","tag":"in","listen":"0.0.0.0","listen_port":1080}],
 "outbounds":[{"type":"ssh","tag":"up","server":"${P}ntrsrv","server_port":2222,"user":"$U","password":"$PW"}]}
EOF
docker run -d --name ${P}singbox --network $NET -v $D/xvs-singbox.json:/etc/sing-box/config.json:ro ghcr.io/sagernet/sing-box:latest run -c /etc/sing-box/config.json >/dev/null 2>&1
sleep 4
probe ${P}singbox:1080 >/dev/null && echo "方向C sing-box ssh出站 → NTR-ssh服务端 : PASS" || echo "方向C : FAIL"

########## 方向 D:mihomo ssh 出站 → NTR ssh 服务端 ##########
cat > $D/xvs-mihomo.yaml <<EOF
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - {name: sshout, type: ssh, server: ${P}ntrsrv, port: 2222, username: $U, password: "$PW"}
rules: ["MATCH,sshout"]
EOF
docker run -d --name ${P}mihomo --network $NET -v $D/xvs-mihomo.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
sleep 5
probe ${P}mihomo:1080 >/dev/null && echo "方向D mihomo ssh出站 → NTR-ssh服务端 : PASS" || echo "方向D : FAIL"
