# -*- coding: utf-8 -*-
"""从 muse (ota_2) 切回 WiFi 审计固件 (ota_0), 不动分区表。

原理: 设备 otadata 两个扇区都有效:
  sector0 @0xD000: seq=1 -> ota_0 (audit/WiFi), CRC 已验证
  sector1 @0xE000: seq=3 -> ota_2 (muse), CRC 已验证
bootloader 取 seq 最大者启动 (当前 = muse)。
最小改动 = 把 sector1 擦成全 0xFF, 只剩 sector0 有效 -> 回落到 ota_0。
不重写任何 ota_select 条目 (避免 CRC 算法/布局踩坑), 复用设备原始已验证数据。

顺带把当前构建的 WiFi 固件重刷到 ota_0 (0x10000), 确保镜像是最新且完整。

用法:
  python tools/switch-to-wifi.py                # 默认 COM5 (CH340)
  python tools/switch-to-wifi.py --port COM3    # 原生 USB CDC 可用时
"""
import argparse, os, struct, subprocess, sys

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
ESPTOOL = r"C:\Users\Oracle.Z\.platformio\packages\tool-esptool\esptool.exe"
FW = r"E:\code\ESP32\firmware\.pio\build\esp32c5_16mb\firmware.bin"
BLANK = r"E:\code\ESP32\tools\otadata-blank.bin"

# 默认 COM5: 这块 C5N16R8 射频反复重启后原生 USB CDC (COM3) 常常不再枚举,
# CH340 UART 始终可用 (见全局 AGENTS.md 的串口坑)。
parser = argparse.ArgumentParser(
    description="从 muse (ota_2) 切回 WiFi 审计固件 (ota_0), 不动分区表")
parser.add_argument("--port", default="COM5",
                    help="串口号, 默认 COM5 (CH340 UART)")
parser.add_argument("--baud", type=int, default=921600,
                    help="烧录波特率, 默认 921600")
args = parser.parse_args()

# 1. 校验固件
fw = open(FW, "rb").read()
if fw[0] != 0xE9:
    print("!! firmware.bin 不是有效 app 镜像 (magic=0x%02X)" % fw[0])
    sys.exit(1)
print("固件: %s  %d 字节 (0x%X)  magic=0xE9 OK" % (FW, len(fw), len(fw)))

# 2. 生成 0x1000 全 FF (擦 otadata sector1)
open(BLANK, "wb").write(b"\xff" * 0x1000)
print("已生成 %s (0x1000 全 0xFF)" % BLANK)

# 3. 一次 write_flash: app -> ota_0, 擦 otadata sector1
cmd = [
    ESPTOOL, "--chip", "esp32c5", "--port", args.port, "--baud", str(args.baud),
    "write_flash",
    "0x10000", FW,       # WiFi 固件 -> ota_0
    "0xE000", BLANK,     # otadata sector1 -> 全 FF (去掉指向 muse 的条目)
]
print("\n执行:", " ".join(cmd))
r = subprocess.run(cmd, capture_output=True, text=True)
tail = [l for l in (r.stdout + r.stderr).splitlines() if l.strip()]
for l in tail[-8:]:
    print("  ", l)
if r.returncode != 0:
    print("!! write_flash 失败 (rc=%d)" % r.returncode)
    sys.exit(r.returncode)
print("\n== 完成: ota_0 已刷入最新 WiFi 固件, otadata 仅剩 sector0(seq=1->ota_0) 有效 ==")
print("   复位后应启动 WiFi 审计固件, AP = WiFi-12F9")
