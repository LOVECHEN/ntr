#!/bin/bash
# NTR 官方构建脚本。纯静态 CGO_ENABLED=0。
#
# ★ 必带 http2legacy build tag:Go 1.27 起 golang.org/x/net/http2 默认转发到标准库 net/http,
#   后者严格拒 sing-mux(h2mux)构造的 nil Request.Header,导致 mux h2mux 客户端不可用。
#   http2legacy 让 x/net 用自带(宽松)http2 实现,h2mux 客户端恢复。smux/yamux 不受影响。
#   (NTR mux 默认走 smux,即使不带此 tag 也可用;此 tag 只为让【显式 h2mux 客户端】也能用。)
#
# 用法:
#   ./build.sh                      # 本机 OS/ARCH
#   GOOS=linux GOARCH=amd64 ./build.sh
#   TAGS="with_wireguard with_connectip" ./build.sh   # 追加可选特性 tag
set -eu
cd "$(dirname "$0")"

TAGS="http2legacy ${TAGS:-}"
OUT="${OUT:-ntr}"

echo "构建 NTR:GOOS=${GOOS:-$(go env GOOS)} GOARCH=${GOARCH:-$(go env GOARCH)} tags=[$TAGS]"
CGO_ENABLED=0 go build -tags "$TAGS" -trimpath -ldflags "-s -w" -o "$OUT" ./cmd/ntr
echo "产物:$OUT ($(du -h "$OUT" | cut -f1))"
