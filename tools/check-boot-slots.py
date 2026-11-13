# -*- coding: utf-8 -*-
"""检查 otadata 结构 / 各槽镜像头 / 与本地固件对比"""
import os, sys, hashlib
sys.stdout.reconfigure(encoding="utf-8")
t = r"C:\Users\Oracle.Z\AppData\Local\Temp\opencode"
d = open(os.path.join(t, "otadata.bin"), "rb").read()
print("== otadata 两个扇区前 96 字节 ==")
for sec in range(2):
    print(" sector%d:" % sec)
    for r in range(0, 96, 16):
        print("   +0x%02X" % r, d[sec * 0x1000 + r: sec * 0x1000 + r + 16].hex(" "))
print()
for name in ("s0", "s1", "s2"):
    b = open(os.path.join(t, name + ".bin"), "rb").read()
    print("%s 头 16 字节: %s" % (name, b[:16].hex(" ")))
fw = open(r"E:\code\ESP32\firmware\.pio\build\esp32c5_16mb\firmware.bin", "rb").read()
print("本地 firmware.bin 头 16 字节:", fw[:16].hex(" "))
print("本地 firmware.bin 大小: %d (0x%X)" % (len(fw), len(fw)))
