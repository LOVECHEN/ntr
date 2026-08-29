#!/bin/bash
# 跑全部 ix-*.sh 跨实现互通脚本,汇总 → results.tsv + GitHub Step Summary。
# 设计:build/单测/互通全部在 GitHub Actions 跑(GitHub 算力,公开无限量);本地只改代码、触发、看结果。
# 逐脚本 pass/fail 启发式判定(详细日志上传为 artifact);exit=失败脚本数(有 FAIL 才红,让 CI 状态有意义)。
set -u
D=/tmp/ntr-interop
export NTR_BIN="${NTR_BIN:-$D/ntr}"
mkdir -p "$D"
DIR="$(cd "$(dirname "$0")" && pwd)"
RES="$D/results.tsv"; : > "$RES"
SUM="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
{ echo "## NTR 跨实现互通(xray / mihomo / sing-box 真跑)"; echo; echo "| 脚本 | 结果 | PASS | FAIL |"; echo "|---|:--:|--:|--:|"; } >> "$SUM"

total=0; failed=0; unknown=0
for s in "$DIR"/ix-*.sh; do
  [ -f "$s" ] || continue
  name=$(basename "$s" .sh); total=$((total+1)); log="$D/$name.log"
  timeout 1200 bash "$s" > "$log" 2>&1 || true
  p=$(grep -icE '\bPASS\b|✅|\[OK\]|通\]|通 ' "$log" || true)
  f=$(grep -icE '\bFAIL\b|❌|✗ ' "$log" || true)
  if [ "$f" -gt 0 ]; then st=FAIL; failed=$((failed+1))
  elif [ "$p" -gt 0 ]; then st=PASS
  else st=UNKNOWN; unknown=$((unknown+1)); fi
  printf '%s\t%s\t%s\t%s\n' "$name" "$st" "$p" "$f" >> "$RES"
  echo "| $name | $st | $p | $f |" >> "$SUM"
done

{ echo; echo "**通过 $((total-failed-unknown)) · 失败 $failed · 未判定 $unknown · 共 $total 脚本**"; } >> "$SUM"
echo "interop done: pass=$((total-failed-unknown)) fail=$failed unknown=$unknown total=$total"
# 不因个别失败中断 CI 的报告生成(report/artifact 步骤 always());但把失败数带出去,job 状态如实反映。
exit "$failed"
