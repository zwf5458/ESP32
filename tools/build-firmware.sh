#!/bin/bash
# 编译全部芯片固件镜像并注册到本地烧录台后端
# 前置: PlatformIO (可用 ~/.venvs/platformio) + 工具链/框架包就位
#   - 工具链: 已从 espressif/crosstool-NG 本地注入 (tools/install-toolchain.sh)
#   - 框架包: tools/dl-resume.sh (自动, CDN 断流用断点续传)
# 用法: tools/build-firmware.sh [版本号]   默认 1.0.0
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-1.0.0}"
BASE="${BASE:-http://localhost:8787}"
TOKEN="${ADMIN_TOKEN:-local-admin-token-change-me}"
OUT_DIR="$ROOT/server/firmware"
# C5 需要 tools/install-c5-libs.sh 注入的本地 c5-libs 包 (espressif32 v8 registry 无此包)
CHIPS=(esp32 esp32s2 esp32s3 esp32c3 esp32c5 esp32c6)

mkdir -p "$OUT_DIR"
cd "$ROOT/firmware"

command -v pio >/dev/null 2>&1 || PATH="$HOME/bin:$PATH"
command -v pio >/dev/null 2>&1 || { echo "错误: 未安装 PlatformIO (python3.11 -m venv ~/.venvs/platformio && ~/.venvs/platformio/bin/pip install platformio)"; exit 1; }

for CHIP in "${CHIPS[@]}"; do
  echo "=== 编译 env:$CHIP ==="
  pio run -e "$CHIP" || { echo "[$CHIP] 编译失败, 跳过注册 (该芯片保留旧镜像)"; continue; }

  APP_BIN=".pio/build/${CHIP}/firmware.bin"
  BOOTLOADER=".pio/build/${CHIP}/bootloader.bin"
  PARTITIONS=".pio/build/${CHIP}/partitions.bin"
  [[ -f "$APP_BIN" ]] || { echo "[$CHIP] 未找到 firmware.bin"; continue; }

  MERGED="$OUT_DIR/firmware-${CHIP}-${VERSION}.bin"
  # merge_bin: bootloader + partitions + app → 单镜像, 从 0x0 烧录
  if [[ -f "$BOOTLOADER" && -f "$PARTITIONS" ]]; then
    ~/.venvs/platformio/bin/esptool --chip "$CHIP" merge-bin --pad-to-size 4MB -o "$MERGED" \
      0x0 "$BOOTLOADER" \
      0x8000 "$PARTITIONS" \
      0x10000 "$APP_BIN" | tail -2
  else
    # 数据分区/缺 bootloader (C5/C6 等环境差异) → 直接注册 app (开发调试用)
    cp "$APP_BIN" "$MERGED"
  fi
  echo "[$CHIP] 合并镜像: $MERGED"

  # 注册到后端
  curl -sS -X POST "$BASE/api/admin/firmware/$CHIP" \
    -H "x-admin-token: $TOKEN" -H "Content-Type: application/json" \
    -d "{\"version\": \"$VERSION\", \"sourcePath\": \"$MERGED\"}" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{console.log(JSON.parse(s).ok?"  ✓ 已注册":("  ✗ "+JSON.parse(s).error))})'
done

echo "--- 当前 manifest ---"
curl -sS "$BASE/api/firmware/manifest" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);for(const[k,v]of Object.entries(j.chips))console.log(" ",k,"v"+v.version,(v.size/1024).toFixed(0)+"KB")})'
