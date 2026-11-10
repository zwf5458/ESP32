#!/usr/bin/env python3
"""PlatformIO espressif32 平台补丁 — ESP32-C5 编译支持 (幂等, 可反复执行)

用途: espressif32 v8 registry 缺 framework-arduinoespressif32-esp32c5-libs
      (C5 预编译库) 的包定义, 直接 `pio run -e esp32c5` 会报 KeyError。

本脚本做三件事 (全部幂等):
  1) platform.json 注入 c5-libs 包定义 (optional=false, 必需)
  2) platform.json 把与 C5 无关的 3 个包标 optional=true —
     toolchain-xtensa-esp-elf (Xtensa 芯片用)、两个 gdb (调试用, 编译不需要),
     否则 PIO 会额外下载 ~435MB 无关包, 且版本要求与本地包不符时会反复重试下载
  3) boards/esp32-c5-devkitc-1.json 缺失时从仓库 tools/ 复制

用法:
    python tools/patch-platformio-c5.py
    python -m platformio run -e esp32c5
"""
import json
import os
import shutil
import sys

PIO = os.path.expanduser("~/.platformio")
PLAT = os.path.join(PIO, "platforms", "espressif32")
PLATFORM_JSON = os.path.join(PLAT, "platform.json")
BOARD_DST = os.path.join(PLAT, "boards", "esp32-c5-devkitc-1.json")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOARD_SRC = os.path.join(REPO, "firmware", "tools", "esp32-c5-devkitc-1.json")

# C5 必需: 预编译 Arduino 库
C5_LIBS = ("framework-arduinoespressif32-esp32c5-libs",
           {"type": "framework", "optional": False, "owner": "platformio", "version": "~3.3.12"})

# 与 C5 编译无关: 标 optional, 避免下载 435MB 无关包
NOT_NEEDED = ("toolchain-xtensa-esp-elf", "tool-riscv32-esp-elf-gdb", "tool-xtensa-esp-elf-gdb")


def main():
    if not os.path.isfile(PLATFORM_JSON):
        print(f"✗ 找不到 {PLATFORM_JSON}\n  请先执行: pio pkg install -g -p espressif32")
        return 1

    with open(PLATFORM_JSON, encoding="utf-8") as f:
        data = json.load(f)
    pkgs = data.setdefault("packages", {})

    name, spec = C5_LIBS
    if pkgs.get(name) != spec:
        pkgs[name] = spec
        print(f"✓ platform.json: 注入 {name}")
    else:
        print(f"· platform.json: {name} 已就位")

    changed = []
    for n in NOT_NEEDED:
        if n in pkgs and not pkgs[n].get("optional"):
            pkgs[n]["optional"] = True
            changed.append(n)
    print("✓ platform.json: 标 optional " + ", ".join(changed) if changed else "· platform.json: 无关包已是 optional")

    with open(PLATFORM_JSON, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    if not os.path.isfile(BOARD_DST):
        if not os.path.isfile(BOARD_SRC):
            print(f"✗ 缺 board 定义: {BOARD_SRC} 不存在")
            return 1
        os.makedirs(os.path.dirname(BOARD_DST), exist_ok=True)
        shutil.copyfile(BOARD_SRC, BOARD_DST)
        print(f"✓ boards: 已安装 esp32-c5-devkitc-1.json")
    else:
        print("· boards: esp32-c5-devkitc-1.json 已就位")

    # builder riscv 工具链映射
    builder = os.path.join(PLAT, "builder", "main.py")
    if os.path.isfile(builder):
        with open(builder, encoding="utf-8") as f:
            src = f.read()
        if 'mcu in ("esp32c3", "esp32c6")' in src:
            src = src.replace('mcu in ("esp32c3", "esp32c6")',
                              'mcu in ("esp32c3", "esp32c5", "esp32c6")')
            with open(builder, "w", encoding="utf-8", newline="\n") as f:
                f.write(src)
            print("✓ builder/main.py: 已补 esp32c5 riscv 映射")
        else:
            print("· builder/main.py: 已含 esp32c5 映射")

    print("\n完成 — 现在可以: python -m platformio run -e esp32c5")
    return 0


if __name__ == "__main__":
    sys.exit(main())
