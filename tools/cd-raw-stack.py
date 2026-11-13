# -*- coding: utf-8 -*-
"""arduino_events 栈顶原始字 + 每个 0x4081xxxx/0x420xxxxx 字的精确函数归属 (nm 符号区间)"""
import struct, subprocess, sys, bisect

sys.stdout.reconfigure(encoding="utf-8")
CD = "tools/coredump.bin"
ELF = "firmware/.pio/build/esp32c5_16mb/firmware.elf"
NM = r"C:\Users\Oracle.Z\.platformio\packages\toolchain-riscv32-esp\bin\riscv32-esp-elf-nm.exe"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "arduino_events"
DEPTH = int(sys.argv[2]) if len(sys.argv) > 2 else 0x140

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

# 符号表 (按地址排序, 区间归属)
r = subprocess.run(f'"{NM}" -n "{ELF}"', capture_output=True, text=True, shell=True)
syms = []
for line in r.stdout.splitlines():
    parts = line.split()
    if len(parts) == 3 and parts[1].upper() in ("T", "t"):
        try: syms.append((int(parts[0], 16), parts[2]))
        except ValueError: pass
syms.sort()
addrs_only = [a for a, _ in syms]

def who(addr):
    i = bisect.bisect_right(addrs_only, addr) - 1
    if i < 0: return "??"
    a, n = syms[i]
    return f"{n}+0x{addr-a:X}" if addr != a else n

# 找目标任务 TCB → sp
for po, pv, pp, pf in segs:
    seg = data[po:po+pf]
    if pf >= 0x44:
        name = seg[0x34:0x44].split(b"\x00")[0].decode(errors="replace")
        if name == TARGET:
            sp = struct.unpack_from("<I", seg, 0)[0]
            print(f"{TARGET} SP=0x{sp:08X}")
            w = sp & ~3
            for k in range(0, DEPTH, 4):
                raw = pa_read(w + k, 4)
                if not raw: break
                v = struct.unpack("<I", raw)[0]
                mark = ""
                if 0x40810000 <= v < 0x40830000 or 0x42000000 <= v < 0x42200000:
                    mark = f"  → {who(v)}"
                print(f"  [0x{w+k:08X}] 0x{v:08X}{mark}")
            break
