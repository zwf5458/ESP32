#!/bin/bash
# 编译全部芯片固件镜像并注册到本地烧录台后端
# 前置: PlatformIO + 工具链/框架包就位 + 烧录台后端已启动 (默认 localhost:8787)
#   - 工具链: 已从 espressif/crosstool-NG 本地注入 (tools/install-toolchain.sh)
#   - 框架包: tools/dl-resume.sh (自动, CDN 断流用断点续传)
#   - esptool: 自动探测 venv 脚本 / PlatformIO 自带 esptool.exe / PATH
# 用法: tools/build-firmware.sh [版本号]   默认 1.1.0
# 可选环境变量: BASE / ADMIN_TOKEN / ESPTOOL / BUILD_DIR
#   BUILD_DIR 可指向另一个全新目录, 强制无删除的干净全量构建
#   (受限沙箱下批量覆写/删除旧 .o 会被安全策略拦截并导致 scons 挂起)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-1.1.0}"
BASE="${BASE:-http://127.0.0.1:8787}"
TOKEN="${ADMIN_TOKEN:-local-admin-token-change-me}"
# 未配置 ADMIN_TOKEN 时服务端用默认管理口令且只监听 127.0.0.1 (见 server/src/index.js),
# 因此本地默认 BASE 兼容; 远程部署必须 export ADMIN_TOKEN。
OUT_DIR="$ROOT/server/firmware"
# Git Bash/MSYS 下 pwd 形如 /e/code/ESP32, 原生 Windows 程序 (esptool.exe / node)
# 无法识别; cygpath -m 转成 E:/code/ESP32 供 -o 参数与注册接口的 sourcePath 使用。
if command -v cygpath >/dev/null 2>&1; then
  WIN_ROOT="$(cygpath -m "$ROOT")"
else
  WIN_ROOT="$ROOT"
fi
# 构建目录一律使用绝对路径: esptool.exe 等原生 Windows 程序无法解析 Git Bash 的 /e/... 路径。
# 默认用独立的 build-release 目录, 与开发态 `pio run` 的 .pio/build 隔离,
# 避免开发残留的旧对象文件在发布构建时被批量覆写/删除。
BUILD_DIR="${BUILD_DIR:-$ROOT/firmware/.pio/build-release}"
if command -v cygpath >/dev/null 2>&1; then
  WIN_BUILD_DIR="$(cygpath -m "$BUILD_DIR")"
else
  WIN_BUILD_DIR="$BUILD_DIR"
fi
# C5 需要 tools/install-c5-libs.sh 注入的本地 c5-libs 包 (espressif32 v8 registry 无此包)
# esp32c5_16mb 为 16MB 三系统 (Triple-Boot) 专用镜像: env 名与 chip key 一致,
# 但 esptool 的芯片型号仍是 esp32c5 (见下方 ESPTOOL_CHIP 映射)。
CHIPS=(esp32 esp32s2 esp32s3 esp32c3 esp32c5 esp32c5_16mb esp32c6)

mkdir -p "$OUT_DIR"
cd "$ROOT/firmware"

command -v pio >/dev/null 2>&1 || PATH="$HOME/bin:$PATH"
command -v pio >/dev/null 2>&1 || { echo "错误: 未安装 PlatformIO (python3.11 -m venv ~/.venvs/platformio && ~/.venvs/platformio/bin/pip install platformio)"; exit 1; }

# esptool 探测: 优先 PlatformIO venv 脚本, 回退到工具链自带的 esptool.exe / PATH。
# 用 ESPTOOL 环境变量可显式指定。
ESPTOOL="${ESPTOOL:-}"
if [[ -z "$ESPTOOL" ]]; then
  if [[ -x "$HOME/.venvs/platformio/bin/esptool" ]]; then
    ESPTOOL="$HOME/.venvs/platformio/bin/esptool"
  elif [[ -x "$HOME/.platformio/packages/tool-esptool/esptool.exe" ]]; then
    ESPTOOL="$HOME/.platformio/packages/tool-esptool/esptool.exe"
  elif command -v esptool >/dev/null 2>&1; then
    ESPTOOL="$(command -v esptool)"
  else
    echo "错误: 未找到 esptool (需 PlatformIO 的 tool-esptool 包, 或 pip install esptool)"; exit 1
  fi
fi
echo "[preflight] esptool: $ESPTOOL"
curl -fsS --max-time 3 "$BASE/api/health" >/dev/null \
  || { echo "错误: 烧录台服务不可达 ($BASE), 请先启动: node server/src/index.js"; exit 1; }

for CHIP in "${CHIPS[@]}"; do
  echo "=== 编译 env:$CHIP ==="
  # pio run 没有 --build-flag 选项; 版本宏经 PLATFORMIO_BUILD_FLAGS 注入,
  # PlatformIO 会把它追加到 platformio.ini 的 build_flags 之后 (main.cpp 另有 #ifndef 兜底)。
  # --disable-auto-clean 避免配置变更时批量删除整个构建目录。
  PLATFORMIO_BUILD_DIR="$WIN_BUILD_DIR" \
  PLATFORMIO_BUILD_FLAGS="-DFW_VERSION=\\\"$VERSION\\\"" \
    pio run -e "$CHIP" --disable-auto-clean \
    || { echo "[$CHIP] 编译失败, 跳过注册 (该芯片保留旧镜像)"; continue; }

  APP_BIN="$WIN_BUILD_DIR/${CHIP}/firmware.bin"
  BOOTLOADER="$WIN_BUILD_DIR/${CHIP}/bootloader.bin"
  PARTITIONS="$WIN_BUILD_DIR/${CHIP}/partitions.bin"
  [[ -f "$APP_BIN" ]] || { echo "[$CHIP] 未找到 firmware.bin"; continue; }

  MERGED="$OUT_DIR/firmware-${CHIP}-${VERSION}.bin"
  WIN_MERGED="$WIN_ROOT/server/firmware/firmware-${CHIP}-${VERSION}.bin"
  # merge_bin: bootloader + partitions + app → 单镜像 (整片从 0x0 烧录)
  # bootloader 偏移由芯片 ROM 规定, 三方一致 (arduino boards.txt / IDF sdkconfig
  # CONFIG_BOOTLOADER_OFFSET_IN_FLASH / esptool BOOTLOADER_FLASH_OFFSET):
  #   esp32 / esp32s2 = 0x1000 ; esp32c5 = 0x2000 ; 其余 = 0x0
  # 注意: espressif32 v8 的 platformio-build.py 把 esp32c5 也当成 0x0 (平台适配缺陷),
  #       因此这里必须显式按芯片指定, 不可沿用 pio upload 的默认。
  # esp32c5_16mb 是同一个物理芯片的 16MB 三系统镜像, esptool 仍按 esp32c5 处理。
  ESPTOOL_CHIP="$CHIP"
  case "$CHIP" in
    esp32|esp32s2)      BL_OFFSET="0x1000" ;;
    esp32c5)            BL_OFFSET="0x2000" ;;
    esp32c5_16mb)       BL_OFFSET="0x2000"; ESPTOOL_CHIP="esp32c5" ;;
    *)                  BL_OFFSET="0x0" ;;
  esac
  if [[ -f "$BOOTLOADER" && -f "$PARTITIONS" ]]; then
    # pad 到 4MB: 只覆盖 ota_0 (0x10000~0x3FFFFF) 的范围, 不会碰 ota_1 (0x400000)
    # 与 ota_2 (0x7F0000), 因此重刷审计固件不会清掉已写入的 ESPsoup/Muse。
    "$ESPTOOL" --chip "$ESPTOOL_CHIP" merge-bin --pad-to-size 4MB -o "$WIN_MERGED" \
      "$BL_OFFSET" "$BOOTLOADER" \
      0x8000 "$PARTITIONS" \
      0x10000 "$APP_BIN" | tail -2
    echo "[$CHIP] bootloader @ $BL_OFFSET (esptool chip: $ESPTOOL_CHIP)"
  else
    # 数据分区/缺 bootloader (C5/C6 等环境差异) → 直接注册 app (开发调试用)
    cp "$APP_BIN" "$MERGED"
  fi
  echo "[$CHIP] 合并镜像: $MERGED"

  # 注册到后端
  curl -sS -X POST "$BASE/api/admin/firmware/$CHIP" \
    -H "x-admin-token: $TOKEN" -H "Content-Type: application/json" \
    -d "{\"version\": \"$VERSION\", \"sourcePath\": \"$WIN_MERGED\"}" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{console.log(JSON.parse(s).ok?"  ✓ 已注册":("  ✗ "+JSON.parse(s).error))})'
done

echo "--- 当前 manifest ---"
curl -sS "$BASE/api/firmware/manifest" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);for(const[k,v]of Object.entries(j.chips))console.log(" ",k,"v"+v.version,(v.size/1024).toFixed(0)+"KB")})'
