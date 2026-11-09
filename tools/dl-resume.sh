#!/bin/bash
# 断点续传下载 PlatformIO 工具链包
# CDN (dl.registry.platformio.org) 对大文件限速断流 → 原理: 302 跳到 GitHub mirror,
# 总大小在各响应的 x-pio-content-length 头。对最终 URL 用 curl -C - 反复续传。
# 用法: tools/dl-resume.sh <注册表文件名> 例: toolchain-riscv32-esp-darwin_arm64-14.2.0+20260121.tar.gz
set -u
DLDIR=~/pio-dl
mkdir -p "$DLDIR"
UA="PlatformIO/6.2.0 (darwin_arm64)"

for FNAME in "$@"; do
  # 文件名两种形态:
  #  A: <pkg>-darwin_arm64-<ver>.tar.gz   (PKGNAMEdarwin 版, 如 tool-esptool-darwin_arm64-2.50400.0.tar.gz)
  #  B: <pkg>-<ver>.tar.gz                (framework 全架构包, 如 framework-arduinoespressif32-4.30312.261024.tar.gz)
  if [[ "$FNAME" == *-darwin_arm64-* ]]; then
    PKGNAME=$(echo "$FNAME" | sed -E 's/^(.*)-darwin_arm64-.*$/\1/')
    VER=$(echo "$FNAME" | sed -E "s/^${PKGNAME}-darwin_arm64-(.*)\.tar\.gz$/\1/")
  else
    VER=$(echo "$FNAME" | sed -E 's/^.*-([0-9]+\.[0-9]+\.[0-9]+(\+[0-9]+)?)\.tar\.gz$/\1/')
    PKGNAME="${FNAME%.tar.gz}"; PKGNAME="${PKGNAME%%-$VER}"
  fi
  [[ -n "$PKGNAME" && -n "$VER" ]] || { echo "    ✗ 解析失败: $FNAME"; exit 1; }
  URL="https://dl.registry.platformio.org/download/platformio/tool/${PKGNAME}/${VER}/${FNAME}"
  echo "=== $PKGNAME @ $VER"

  # 拿跳转 + 真实大小 (瞬时 504 风暴 → 重试)
  TOT=""; REAL_URL=""
  for i in $(seq 1 60); do
    HDRS=$(curl -s -D - -o /dev/null -A "$UA" "$URL")
    REAL_URL=$(echo "$HDRS" | grep -i '^location:' | tail -1 | sed 's/^[Ll]ocation: //' | tr -d '\r')
    TOT=$(echo "$HDRS" | grep -i '^x-pio-content-length:' | tail -1 | tr -d '\r' | awk '{print $2}')
    if [[ "$TOT" =~ ^[0-9]+$ ]]; then break; fi
    sleep 5
  done
  [[ -z "$REAL_URL" ]] && REAL_URL="$URL"
  [[ "$TOT" =~ ^[0-9]+$ ]] || { echo "    ✗ 取大小失败"; exit 1; }
  echo "    目标: $REAL_URL (bytes=$TOT)"

  for i in $(seq 1 400); do
    GOT=$(stat -f%z "$DLDIR/$FNAME" 2>/dev/null || echo 0)
    if [[ "$GOT" == "$TOT" ]]; then break; fi
    if (( i % 10 == 1 )); then echo "    已传 $GOT / $TOT"; fi
    # 关键: 302 跳转后 GitHub asset URL 是时效性签名; 直接用原 URL 加 -L follow,
    # 空文件/续传皆可 (-C - 自动处理 range)
    curl -sS --fail -L --proto '=https' -C - --connect-timeout 15 -A "$UA" -o "$DLDIR/$FNAME" "$URL" || sleep 2
  done
  GOT=$(stat -f%z "$DLDIR/$FNAME" 2>/dev/null || echo 0)
  if [[ "$GOT" == "$TOT" ]]; then
    echo "    ✓ $PKGNAME 完成"
  else
    echo "    ✗ $PKGNAME 未完成 ($GOT/$TOT)"; exit 1
  fi
done
