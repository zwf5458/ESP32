#!/usr/bin/env python3
"""PlatformIO 后置脚本: 修正 ESP32-C5 的 bootloader 烧录偏移。

背景:
  framework-arduinoespressif32/tools/platformio-build.py 里 FLASH_EXTRA_IMAGES
  对 riscv 芯片统一用 0x0000 (只有 esp32/esp32s2 是 0x1000), 但 ESP32-C5 的
  二阶段 bootloader 实际位于 flash **0x2000** (Arduino boards.txt 里
  esp32c5.build.bootloader_addr=0x2000, PlatformIO 不读该文件)。

  `pio run -t upload` 因此会把 bootloader 写到 0x0: 应用镜像 (0x10000) 本身是对的,
  但 ROM 在 0x2000 读不到合法镜像头, 上电后串口反复打印
      invalid header: 0xa8030007
      assertion "result == ETS_OK" failed: file "ets_main.c" ... ets_flash_boot
  表现为无限复位循环。

  pre: 脚本运行时框架还没追加 FLASH_EXTRA_IMAGES, 所以只能在 post: 阶段同时修正
  FLASH_EXTRA_IMAGES 与已经展开的 UPLOADERFLAGS。仅对 esp32c5 生效。
"""

import os  # noqa: F401  (保留以兼容脚本被直接执行时的相对路径处理)

try:
    Import("env")  # noqa: F821
except NameError:  # 被当作普通 python 模块导入时 (仅为 lint / 手动执行)
    env = None

C5_BOOTLOADER_OFFSET = "0x2000"
WRONG_OFFSETS = ("0x0", "0x0000", "0x1000")


def _is_bootloader_image(value):
    text = str(value).replace("\\", "/")
    return text.endswith("bootloader.bin")


def _fix_extra_images(env):
    images = list(env.get("FLASH_EXTRA_IMAGES", []))
    changed = False
    fixed = []
    for offset, path in images:
        if _is_bootloader_image(path) and str(offset).lower() in WRONG_OFFSETS:
            offset = C5_BOOTLOADER_OFFSET
            changed = True
        fixed.append((offset, path))
    if changed:
        env.Replace(FLASH_EXTRA_IMAGES=fixed)
    return changed


def _fix_uploader_flags(env):
    flags = list(env.get("UPLOADERFLAGS", []))
    changed = False
    for i, value in enumerate(flags):
        if i > 0 and _is_bootloader_image(value) and str(flags[i - 1]).lower() in WRONG_OFFSETS:
            flags[i - 1] = C5_BOOTLOADER_OFFSET
            changed = True
    if changed:
        env.Replace(UPLOADERFLAGS=flags)
    return changed


def main(env):
    mcu = str(env.BoardConfig().get("build.mcu", ""))
    if mcu != "esp32c5":
        return
    changed = _fix_extra_images(env)
    changed = _fix_uploader_flags(env) or changed
    if changed:
        print("[fix_c5_bootloader] bootloader 烧录偏移 -> %s" % C5_BOOTLOADER_OFFSET)


if env is not None:
    main(env)
