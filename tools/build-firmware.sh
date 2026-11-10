#!/bin/bash
# 编译全部芯片固件镜像并注册到本地烧录台后端
# 前置: PlatformIO (可用 ~/.venvs/platformio) + 工具链/框架包就位
#   - 工具链: 已从 espressif/crosstool-NG 本地注入 (tools/install-toolchain.sh)
#   - 框架包: tools/dl-resume.sh (自动, CDN 断流用断点续传)
# 用法: tools/build-firmware.sh [版本号]   默认 1.1.0
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-1.1.0}"
BASE="${BASE:-http://localhost:8787}"
TOKEN="${ADMIN_TOKEN:-local-admin-token-change-me}"
# 未配置 ADMIN_TOKEN 时服务端禁用管理接口且只监听 127.0.0.1 (见 server/src/index.js),
# 因此本地默认 BASE 兼容; 远程部署必须 export ADMIN_TOKEN。
OUT_DIR="$ROOT/server/firmware"
# C5 需要 tools/install-c5-libs.sh 注入的本地 c5-libs 包 (espressif32 v8 registry 无此包)
CHIPS=(esp32 esp32s2 esp32s3 esp32c3 esp32c5 esp32c6)

mkdir -p "$OUT_DIR"
cd "$ROOT/firmware"

command -v pio >/dev/null 2>&1 || PATH="$HOME/bin:$PATH"
command -v pio >/dev/null 2>&1 || { echo "错误: 未安装 PlatformIO (python3.11 -m venv ~/.venvs/platformio && ~/.venvs/platformio/bin/pip install platformio)"; exit 1; }

for CHIP in "${CHIPS[@]}"; do
  echo "=== 编译 env:$CHIP ==="
  pio run -e "$CHIP" --build-flag "-DFW_VERSION=\\\"$VERSION\\\"" \
    || { echo "[$CHIP] 编译失败, 跳过注册 (该芯片保留旧镜像)"; continue; }

  APP_BIN=".pio/build/${CHIP}/firmware.bin"
  BOOTLOADER=".pio/build/${CHIP}/bootloader.bin"
  PARTITIONS=".pio/build/${CHIP}/partitions.bin"
  [[ -f "$APP_BIN" ]] || { echo "[$CHIP] 未找到 firmware.bin"; continue; }

  MERGED="$OUT_DIR/firmware-${CHIP}-${VERSION}.bin"
  # merge_bin: bootloader + partitions + app → 单镜像 (整片从 0x0 烧录)
  # bootloader 偏移由芯片 ROM 规定, 三方一致 (arduino boards.txt / IDF sdkconfig
  # CONFIG_BOOTLOADER_OFFSET_IN_FLASH / esptool BOOTLOADER_FLASH_OFFSET):
  #   esp32 / esp32s2 = 0x1000 ; esp32c5 = 0x2000 ; 其余 = 0x0
  # 注意: espressif32 v8 的 platformio-build.py 把 esp32c5 也当成 0x0 (平台适配缺陷),
  #       因此这里必须显式按芯片指定, 不可沿用 pio upload 的默认。
  case "$CHIP" in
    esp32|esp32s2) BL_OFFSET="0x1000" ;;
    esp32c5)       BL_OFFSET="0x2000" ;;
    *)             BL_OFFSET="0x0" ;;
  esac
  if [[ -f "$BOOTLOADER" && -f "$PARTITIONS" ]]; then
    ~/.venvs/platformio/bin/esptool --chip "$CHIP" merge-bin --pad-to-size 4MB -o "$MERGED" \
      "$BL_OFFSET" "$BOOTLOADER" \
      0x8000 "$PARTITIONS" \
      0x10000 "$APP_BIN" | tail -2
    echo "[$CHIP] bootloader @ $BL_OFFSET"
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
