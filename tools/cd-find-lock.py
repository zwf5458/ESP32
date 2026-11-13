# -*- coding: utf-8 -*-
"""从 coredump 定位 loopTask 阻塞的队列/信号量:
TCB → xEventListItem (pvOwner==TCB) → pxContainer (队列等待列表) → 队列对象地址
→ 在 ELF 符号表/邻域中辨认归属。
"""
import struct, subprocess, sys, re

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
CD = "tools/coredump.bin"
ELF = "firmware/.pio/build/esp32c5_16mb/firmware.elf"
NM = r"C:\Users\Oracle.Z\.platformio\packages\toolchain-riscv32-esp\bin\riscv32-esp-elf-nm.exe"

data = open(CD, "rb").read()[0x18:]
phoff = struct.unpack_from("<I", data, 0x1C)[0]
phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
segs = []
for i in range(phnum):
    o = phoff + i * phentsize
    ptype, poff, pva, ppa, pfilesz, pmemsz = struct.unpack_from("<IIIIII", data, o)
    if ptype == 1 and pfilesz:
        segs.append((poff, pva, ppa, pfilesz))

def pa_read(pa, n):
    for poff, pva, ppa, filesz in segs:
        if ppa <= pa < ppa + filesz:
            o = poff + (pa - ppa)
            return data[o:o+n]
    return None

# 找 loopTask TCB
tcb = None
for poff, pva, ppa, filesz in segs:
    blob = data[poff:poff+filesz]
    i = blob.find(b"loopTask")
    if i >= 0:
        tcb = ppa + i - 0x34
        break
if tcb is None:
    print("loopTask TCB 未找到"); sys.exit(1)

print(f"loopTask TCB @ 0x{tcb:08X}")
raw = pa_read(tcb, 0x60)
words = struct.unpack("<24I", raw)
for k, w in enumerate(words):
    print(f"  +0x{k*4:02X}: 0x{w:08X}")

# xEventListItem: 在 TCB 内找 pvOwner == tcb 的 20 字节块 (ListItem: next,prev,container,value,owner)
item_off = None
for off in range(0, 0x40, 4):
    if len(raw) < off + 20: break
    nxt, prv, cont, val, owner = struct.unpack_from("<IIIII", raw, off)
    if owner == tcb and (tcb - 0x400) < nxt < (tcb + 0x40000):
        item_off = off
        print(f"\nListItem @ +0x{off:02X}: next=0x{nxt:08X} prev=0x{prv:08X} container=0x{cont:08X} value={val} owner=0x{owner:08X}")
if item_off is None:
    print("\n未找到 pvOwner==TCB 的列表项 (任务可能不在等待列表)"); sys.exit(0)

# container 是队列内的 xTasksWaitingToSend 或 xTasksWaitingToReceive
cont = words[item_off // 4 + 2]
# Queue_t 布局: pcHead(0) pcTail(4) pcWriteTo(8) pcReadFrom(12) xTasksWaitingToSend(16) xTasksWaitingToReceive(36) ...
qbase_send = cont - 16
qbase_recv = cont - 36
print(f"等待列表容器 0x{cont:08X} → 队列对象候选: send列表 base=0x{qbase_send:08X} / recv列表 base=0x{qbase_recv:08X}")

# 符号表查归属
r = subprocess.run(f'"{NM}" "{ELF}"', capture_output=True, text=True, shell=True)
syms = []
for line in r.stdout.splitlines():
    parts = line.split()
    if len(parts) == 3 and parts[1].upper() in ("B", "D", "b", "d"):
        try: syms.append((int(parts[0], 16), parts[2]))
        except ValueError: pass
syms.sort()
def near(addr):
    out = []
    for a, n in syms:
        if abs(a - addr) < 0x180:
            out.append(f"{n} @0x{a:08X} (Δ{a-addr:+#x})")
    return out

for cand in (qbase_send, qbase_recv):
    nl = near(cand)
    print(f"\n队列候选 0x{cand:08X} 最近的静态符号:")
    for s in nl[:6]: print("   ", s)
    # dump 队列头内容
    qraw = pa_read(cand, 0x48)
    if qraw:
        qw = struct.unpack("<18I", qraw)
        print("   内容:", " ".join(f"0x{w:08X}" for w in qw[:12]))
