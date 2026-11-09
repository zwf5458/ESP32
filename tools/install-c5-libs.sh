#!/bin/bash
# 注入 ESP32-C5 固件编译支持 (espressif32 v8 registry 缺 c5-libs 的完整对策)
# 1) 下载 espressif/esp32-arduino-lib-builder idf-release_v5.5-b774170f-v3.zip (~666MB)
# 2) 提取 esp32c5 预编译库 → 安装为 framework-arduinoespressif32-esp32c5-libs
# 3) 补 platform.json 包定义 / boards/esp32-c5-devkitc-1.json / builder riscv 映射
# 与 espressif32 v8 (arduino core 3.3.12, IDF v5.5.5 b774170ff46) 精确对应
set -euo pipefail
DLDIR=~/pio-dl
PKG=~/.platformio/packages
PLAT=~/.platformio/platforms/espressif32
ZIP="$DLDIR/c5-libs-full.zip"
URL="https://github.com/espressif/esp32-arduino-lib-builder/releases/download/idf-release_v5.5/esp32-arduino-libs-idf-release_v5.5-b774170f-v3.zip"

# ---------- 1) 下载 (断点续传) ----------
if [[ ! -f "$ZIP" ]]; then
  mkdir -p "$DLDIR"
  for i in $(seq 1 3000); do
    curl -sS --fail -L -C - --connect-timeout 15 -o "$ZIP" "$URL" && break
    sleep 3
  done
fi
[[ $(stat -f%z "$ZIP") -gt 600000000 ]] || { echo "✗ zip 不完整"; exit 1; }

# ---------- 2) 解压 + 安装 ----------
EXTRACT="$DLDIR/c5-libs"
if [[ ! -d "$EXTRACT/esp32-arduino-libs/esp32c5/lib" ]]; then
  unzip -q -o "$ZIP" -d "$EXTRACT"
fi
SRC="$EXTRACT/esp32-arduino-libs/esp32c5"

DEST="$PKG/framework-arduinoespressif32-esp32c5-libs"
rm -rf "$DEST"; mkdir -p "$DEST"
for d in bin dio_qspi flags include ld lib qio_qspi; do cp -R "$SRC/$d" "$DEST/"; done
cp "$SRC/sdkconfig" "$SRC/versions.txt" "$DEST/"
cat > "$DEST/package.json" <<'EOF'
{
  "name": "framework-arduinoespressif32-esp32c5-libs",
  "version": "3.3.12",
  "description": "ESP-IDF support files for the ESP32 Arduino core (ESP32-C5)",
  "keywords": ["framework","arduino","espressif","esp32c5"],
  "license": "LGPL-2.1-or-later",
  "repository": {"type": "git", "url": "https://github.com/espressif/arduino-esp32"}
}
EOF
cat > "$DEST/.piopm" <<'EOF'
{
  "type": "framework",
  "name": "framework-arduinoespressif32-esp32c5-libs",
  "version": "3.3.12",
  "spec": {"owner": "platformio", "id": null, "name": "framework-arduinoespressif32-esp32c5-libs", "requirements": "~3.3.12", "uri": null}
}
EOF
echo "✓ libs 包已安装: $DEST ($(du -sh "$DEST" | cut -f1))"

# ---------- 3) 平台三处补丁 ----------
# 3a. platform.json 补包定义 (备份一次)
node -e '
const fs=require("fs");
const p=process.env.HOME+"/.platformio/platforms/espressif32/platform.json";
const j=JSON.parse(fs.readFileSync(p));
if(!fs.existsSync(p+".bak")) fs.writeFileSync(p+".bak", JSON.stringify(j,null,2));
j.packages["framework-arduinoespressif32-esp32c5-libs"]={type:"framework",optional:true,owner:"platformio",version:"~3.3.12"};
fs.writeFileSync(p, JSON.stringify(j,null,2));'
echo "✓ platform.json 已补 c5-libs 定义"

# 3b. board 定义 (文件随仓库保管, 若缺失则复刻)
if [[ ! -f "$PLAT/boards/esp32-c5-devkitc-1.json" ]]; then
  echo "✗ 缺 boards/esp32-c5-devkitc-1.json — 请从仓库 tools/esp32-c5-devkitc-1.json 复制"
  exit 1
fi

# 3c. builder main.py: esp32c5 → riscv 工具链映射
python3 - <<'EOF'
import os, re
p = os.path.expanduser("~/.platformio/platforms/espressif32/builder/main.py")
s = open(p).read()
if 'mcu in ("esp32c3", "esp32c6")' in s:
    s = s.replace('mcu in ("esp32c3", "esp32c6")', 'mcu in ("esp32c3", "esp32c5", "esp32c6")')
    open(p, "w").write(s)
    print("✓ builder main.py 已补 esp32c5 riscv 映射")
else:
    print("✓ builder main.py 已包含 esp32c5 映射")
EOF

export PATH="$HOME/bin:$PATH"
pio pkg list --global 2>/dev/null | grep -E "c5|✓|框架" || true
echo "完成 — 可运行: pio run -e esp32c5"
