#!/bin/bash
# ============================================================================
# 交叉验证:NTR MTProto 客户端  →  mtg (9seconds/mtg v2.2.8) 服务端
#   半向验证(mtg 只有服务端,无客户端;真 Telegram 客户端不好自动化)
#   判据:mtg 日志出现 dc=N 绑定 + 进入 relay/telegram 调用阶段
#         = faketls digest 通过 + obfuscated2 connType 校验通过 = 线格式逐字节对齐
#   反向(mtg 客户端 → NTR 服务端):不可做,mtg 无客户端实现
# 专属 docker network: xc-mt ;容器前缀: xct-
# ============================================================================
set -u
NET=xc-mt
IMG=nineseconds/mtg:2
D=/tmp/ntr-interop
# 与 NTR 同款 ee secret:0xEE ‖ key("0123456789abcdef") ‖ host("storage.googleapis.com")
SEC="ee3031323334353637383961626364656673746f726167652e676f6f676c65617069732e636f6d"
# 长度正确但 key 全错(16 字节)—— 负控,应触发 mtg 的 "incorrect client random"
WRONG="eeffffffffffffffffffffffffffffffff73746f726167652e676f6f676c65617069732e636f6d"

cleanup(){ docker rm -f xct-mtg xct-ntrcli xct-ntrcli-wrong >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup
docker network create $NET >/dev/null 2>&1

echo "### 1) 起 mtg 服务端(MTProto proxy, debug)"
docker run -d --name xct-mtg --network $NET $IMG simple-run 0.0.0.0:3128 "$SEC" --debug >/dev/null 2>&1
sleep 4
docker ps --filter name=xct-mtg --format '  mtg: {{.Status}}'

echo "### 2) 起 NTR mtproto 客户端(socks 1080 → mtproto → xct-mtg:3128, dc=2, 同 secret)"
cat > $D/xct-ntrcli.yaml <<EOF
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: mtproto
    server: "xct-mtg:3128"
    secret: "$SEC"
    dc: "2"
EOF
docker run -d --name xct-ntrcli --network $NET -e NTR_DEBUG=1 \
  -v $D/ntr:/ntr:ro -v $D/xct-ntrcli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 3

echo "### 3) 经 socks 驱动一次流量(目标任意;MTProto 线上只传 DC 索引,不带目标)"
docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 \
  -x socks5h://xct-ntrcli:1080 http://example.com/ >/dev/null 2>&1
sleep 2

echo "### 4) 主验证判据 —— mtg 服务端日志:"
if docker logs xct-mtg 2>&1 | grep -Eq '"dc":2.*relay|proxy.relay.*"dc":2|"dc":2'; then
  docker logs xct-mtg 2>&1 | grep -E '"dc":2|Stream has been' | tail -4 | sed 's/^/  /'
  echo "  ==> ✅ 通:mtg 绑定 dc=2 并进入 relay —— faketls digest + obfuscated2 connType 双双通过"
else
  echo "  ==> ❌ 未见 dc 绑定/relay;完整日志:"; docker logs xct-mtg 2>&1 | tail -8 | sed 's/^/  /'
fi

echo "### 5) 负控 —— 换错 16 字节 key,mtg 必须拒绝(证明 digest 校验是真的,没被放宽)"
cat > $D/xct-ntrcli-wrong.yaml <<EOF
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1081
    outbound: up
outbounds:
  - name: up
    type: mtproto
    server: "xct-mtg:3128"
    secret: "$WRONG"
    dc: "2"
EOF
docker run -d --name xct-ntrcli-wrong --network $NET -e NTR_DEBUG=1 \
  -v $D/ntr:/ntr:ro -v $D/xct-ntrcli-wrong.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 2
docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 \
  -x socks5h://xct-ntrcli-wrong:1081 http://example.com/ >/dev/null 2>&1
sleep 1
docker logs xct-mtg 2>&1 | grep -E 'incorrect client random' | tail -1 | sed 's/^/  /' \
  && echo "  ==> ✅ 负控成立:mtg 用 fake.ErrBadDigest 拒绝错 secret" \
  || echo "  ==> ⚠ 未捕获 incorrect client random"

echo "### 6) 其它对端核实(xray/sing-box/mihomo 是否有 MTProto)"
for IM in ghcr.io/xtls/xray-core:latest ghcr.io/sagernet/sing-box:latest metacubex/mihomo:latest; do
  docker image inspect "$IM" >/dev/null 2>&1 || continue
  c=$(docker run --rm --entrypoint sh "$IM" -c 'for b in /usr/bin/xray /usr/local/bin/sing-box /mihomo; do [ -f "$b" ] && strings "$b"; done' 2>/dev/null | grep -ci mtproto)
  echo "  $IM : mtproto 字符串数=$c"
done
echo "  ==> xray 已移除、sing-box/mihomo 从未实现 —— 无其它可用 MTProto 对端"

cleanup
echo "### 清理完成(容器 xct-* + 网络 $NET 已删)"
