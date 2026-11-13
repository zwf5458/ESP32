# -*- coding: utf-8 -*-
"""coredump 全部段中的 flash 代码指针, 按段+地址顺序, addr2line 带函数名"""
import struct, subprocess, sys, re

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
CD = "tools/coredump.bin"
ELF = "firmware/.pio/build/esp32c5_16mb/firmware.elf"
A2L = r"C:\Users\Oracle.Z\.platformio\packages\toolchain-riscv32-esp\bin\riscv32-esp-elf-addr2line.exe"

data = open(CD, "rb").read()[0x18:]
phoff = struct.unpack_from("<I", data, 0x1C)[0]
phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)

segs = []
for i in range(phnum):
    o = phoff + i * phentsize
    ptype, poff, pva, ppa, pfilesz, pmemsz = struct.unpack_from("<IIIIII", data, o)
    if ptype == 1 and pfilesz:
        segs.append((poff, ppa, pfilesz))

allw = []
for poff, ppa, pfilesz in segs:
    for off in range(poff, poff + pfilesz - 3, 4):
        v = struct.unpack_from("<I", data, off)[0]
        if 0x42000000 <= v < 0x42200000 or 0x40810000 <= v < 0x4082C000:
            allw.append((ppa + (off - poff), v))

uniq = list(dict.fromkeys(v for _, v in allw))
arg = " ".join(f"0x{a:X}" for a in uniq)
r = subprocess.run(f'"{A2L}" -pfiaC -e "{ELF}" {arg}', capture_output=True, text=True, shell=True)
sym, cur = {}, []
for line in r.stdout.splitlines():
    if line.startswith("0x"):
        if cur: sym[cur[0].split(":")[0].strip().lower()] = cur
        cur = [line]
    elif line.strip():
        cur.append(line.strip())
if cur: sym[cur[0].split(":")[0].strip().lower()] = cur

print(f"flash 代码指针共 {len(allw)} 个:\n")
last_pa = None
for a, v in allw:
    if last_pa is not None and (a - last_pa) > 0x2000:
        print("  ---- 段边界 ----")
    last_pa = a
    s = sym.get(f"0x{v:x}")
    if not s:
        s = [f"0x{v:08X}: ??"]
    txt = " | ".join(s[1:]) if len(s) > 1 else s[0]
    txt = re.sub(r"/home/runner/work/esp32-arduino-lib-builder/esp32-arduino-lib-builder/esp-idf/", "", txt)
    txt = re.sub(r"C:\\Users\\Oracle.Z\\.platformio\\packages\\framework-arduinoespressif32\\cores\\esp32/", "", txt)
    print(f"  [0x{a:08X}] {txt[:130]}")
