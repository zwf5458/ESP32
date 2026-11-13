# -*- coding: utf-8 -*-
"""dump 指定任务的活跃栈 (从 TCB 的 pxTopOfStack 向栈底) — 支持从段表直接拿栈区间"""
import struct, subprocess, sys, re

sys.stdout.reconfigure(encoding="utf-8")
CD = "tools/coredump.bin"
ELF = "firmware/.pio/build/esp32c5_16mb/firmware.elf"
A2L = r"C:\Users\Oracle.Z\.platformio\packages\toolchain-riscv32-esp\bin\riscv32-esp-elf-addr2line.exe"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "arduino_events"

data = open(CD, "rb").read()[0x18:]
phoff = struct.unpack_from("<I", data, 0x1C)[0]
phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
segs = []
for i in range(phnum):
    o = phoff + i * phentsize
    pt, po, pv, pp, pf, pm = struct.unpack_from("<IIIIII", data, o)
    if pt == 1 and pf:
        segs.append((po, pv, pp, pf))

def pa_read(pa, n):
    for po, pv, pp, pf in segs:
        if pp <= pa < pp + pf:
            return data[po+(pa-pp):po+(pa-pp)+n]
    return None

# 找目标任务的 TCB → sp; 栈区间 = [sp, TCB_pa) (Arduino 布局: 栈在 TCB 下方, sp 向下)
tcbs = {}
for po, pv, pp, pf in segs:
    seg = data[po:po+pf]
    if pf >= 0x44:
        name = seg[0x34:0x44].split(b"\x00")[0].decode(errors="replace")
        if name and len(name) <= 16 and name.isprintable():
            tcbs[name] = (pp, struct.unpack_from("<I", seg, 0)[0])

if TARGET not in tcbs:
    print("tasks:", list(tcbs)); sys.exit(1)
tcb_pa, sp = tcbs[TARGET]
print(f"{TARGET} TCB=0x{tcb_pa:08X} SP=0x{sp:08X}")

# 栈顶 = 本 coredump 中相邻更高端点 (TCB 前的连续栈段): 直接扫 sp 向上 0x600 字节
addrs, labels = [], []
w = sp & ~3
for k in range(0, 0x600, 4):
    raw = pa_read(w + k, 4)
    if not raw:
        break
    v = struct.unpack("<I", raw)[0]
    if 0x42000000 <= v < 0x42200000 or 0x40810000 <= v < 0x40830000:
        addrs.append(f"0x{v:X}")
        labels.append((w + k, v))
    if len(addrs) >= 60:
        break

if not addrs:
    print("(无代码指针)"); sys.exit(0)
r = subprocess.run(f'"{A2L}" -pfiaC -e "{ELF}" ' + " ".join(addrs),
                   capture_output=True, text=True, shell=True)
sym, cur = {}, []
for line in r.stdout.splitlines():
    if line.startswith("0x"):
        if cur: sym[cur[0].split(":")[0].strip().lower()] = cur
        cur = [line]
    elif line.strip():
        cur.append(line.strip())
if cur: sym[cur[0].split(":")[0].strip().lower()] = cur

for (pa, v), a in zip(labels, addrs):
    s = sym.get(a.lower(), [f"0x{v:08X}: ??"])
    txt = " | ".join(s[1:]) if len(s) > 1 else s[0]
    txt = re.sub(r"C:\\Users\\Oracle.Z\\.platformio\\packages\\[^ ]*/", "", txt)
    txt = re.sub(r"/home/runner/work/esp32-arduino-lib-builder/esp32-arduino-lib-builder/esp-idf/", "", txt)
    print(f"  [0x{pa:08X}] {txt[:140]}")
