#!/bin/bash
# 从 espressif/crosstool-NG 官方 release 下载工具链并注入 PlatformIO 全局包
# (PIO registry CDN 对大文件不稳定 → 用官方 mirror + 本地打包)
# 用法: tools/install-toolchain.sh
set -euo pipefail
DLDIR=~/pio-dl
PKG=~/.platformio/packages
mkdir -p "$DLDIR" "$PKG"
TAG=esp-14.2.0_20260121        # 与 espressif32 v8 要求的 toolchain 14.2.0+20260121 对应
BASE="https://github.com/espressif/crosstool-NG/releases/download/$TAG"

dl(){ local url=$1 out=$2; [[ -f "$out" ]] && echo "已有 $out" && return 0
  for i in $(seq 1 3000); do curl -sSL --fail -C - --connect-timeout 20 -o "$out" "$url" && return 0; sleep 3; done
  echo "下载失败: $url"; exit 1; }

dl "$BASE/riscv32-esp-elf-$TAG-aarch64-apple-darwin.tar.xz" "$DLDIR/riscv.tar.xz"
dl "$BASE/xtensa-esp-elf-$TAG-aarch64-apple-darwin.tar.xz"  "$DLDIR/xtensa.tar.xz"

inject(){ # $1: 包名  $2: tarball 里顶层目录名  $3: tarball
  local NAME=$1 TOP=$2 TAR=$3
  echo "注入 $NAME ..."
  rm -rf "$PKG/$NAME"; mkdir -p "$PKG/$NAME"
  tar -C "$PKG/$NAME" -mxJf "$TAR"
  if [[ -d "$PKG/$NAME/$TOP" ]]; then
    rsync -a "$PKG/$NAME/$TOP/" "$PKG/$NAME/" && rm -rf "$PKG/$NAME/$TOP"
    # 双层嵌套情况 (riscv/xten 目标 arch 目录自身重名)
    if [[ -d "$PKG/$NAME/$TOP" ]]; then
      rsync -a "$PKG/$NAME/$TOP/" "$PKG/$NAME/$TOP/" && rm -rf "$PKG/$NAME/$TOP"
    fi
  fi
  cat > "$PKG/$NAME/package.json" <<EOF
{
  "name": "$NAME",
  "version": "14.2.0+20260121",
  "description": "GCC ${NAME} espressif $TAG (local install from crosstool-NG)",
  "keywords": ["espressif", "toolchain"],
  "homepage": "https://github.com/espressif/crosstool-NG/releases/tag/$TAG"
}
EOF
  cat > "$PKG/$NAME/.piopm" <<EOF
{
  "type": "tool",
  "name": "$NAME",
  "version": "14.2.0+20260121",
  "spec": {"owner": "platformio", "id": null, "name": "$NAME", "requirements": "14.2.0+20260121", "uri": null}
}
EOF
}

inject toolchain-riscv32-esp    riscv32-esp-elf "$DLDIR/riscv.tar.xz"
inject toolchain-xtensa-esp-elf xtensa-esp-elf  "$DLDIR/xtensa.tar.xz"

export PATH="$HOME/bin:$PATH"
pio pkg list --global 2>/dev/null | sed -n '/Tools/,$p'
