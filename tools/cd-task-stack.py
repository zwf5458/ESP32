# -*- coding: utf-8 -*-
"""从 coredump 精确还原各任务的活跃栈:
TCB 第一个字段是 pxTopOfStack (preemption 时的 SP), 栈向下生长,
活跃帧 = SP 向下到栈底之间的内容, 最新调用在最前。addr2line 逐字解码。
"""
import struct, subprocess, sys

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
CD = "tools/coredump.bin"
ELF = "firmware/.pio/build/esp32c5_16mb/firmware.elf"
A2L = r"C:\Users\Oracle.Z\.platformio\packages\toolchain-riscv32-esp\bin\riscv32-esp-elf-addr2line.exe"

data = open(CD, "rb").read()[0x18:]
phoff = struct.unpack_from("<I", data, 0x1C)[0]
phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)

segs = []  # (poff, pva, ppa, filesz)
for i in range(phnum):
    o = phoff + i * phentsize
    ptype, poff, pva, ppa, pfilesz, pmemsz = struct.unpack_from("<IIIIII", data, o)
    if ptype == 1 and pfilesz:
        segs.append((poff, pva, ppa, pfilesz))

def pa_read(pa, n=4):
    """按物理地址读 coredump 中的 n 字节"""
    for poff, pva, ppa, filesz in segs:
        if ppa <= pa < ppa + filesz:
            o = poff + (pa - ppa)
            return data[o:o+n]
    return None

def va_read(va, n=4):
    """按虚拟地址读"""
    for poff, pva, ppa, filesz in segs:
        if pva and pva <= va < pva + filesz:
            o = poff + (va - pva)
            return data[o:o+n]
    return None

# 1. 找所有任务名字符串 → TCB
NAMES = [b"loopTask", b"wifi", b"tiT", b"sysWork", b"IDLE", b"async_tcp", b"Tmr"]
seen = set()
tasks = []
for poff, pva, ppa, filesz in segs:
    blob = data[poff:poff+filesz]
    for nm in [b"loopTask", b"tiT\x00", b"wifi\x00", b"IDLE0\x00", b"IDLE1\x00", b"async_tcp",
               b"sysWork\x00", b"Tmr Svc", b"NetworkEve", b"esp_timer", b"ipc0\x00", b"ipc1\x00",
               b"USJ\x00", b"hcd\x00", b"btCont", b"cliMain", b"udp:\x00", b"DHCP\x00", b"emac\x00"]:
        idx = 0
        while True:
            i = blob.find(nm, idx)
            if i < 0: break
            idx = i + 1
            # TCB: pcTaskName 在偏移 0x34 (32位 FreeRTOS: top(4)+list(20)+list(20)+prio(4)+stack(4))
            tcb_pa = ppa + i - 0x34
            if tcb_pa in seen: continue
            seen.add(tcb_pa)
            raw = pa_read(tcb_pa, 0x40)
            if not raw or len(raw) < 0x40: continue
            sp, stack_base, prio, name_off = struct.unpack_from("<IIII", raw, 0)
            nmz = raw[0x34:0x44].split(b"\x00")[0].decode(errors="replace")
            if not nmz or not (0x40800000 <= sp < 0x40900000): continue
            tasks.append((nmz, sp, stack_base, prio))

print("== 任务 TCB (pxTopOfStack = panic 时 SP) ==")
for nmz, sp, base, prio in tasks:
    print(f"  {nmz:<12} SP=0x{sp:08X} stack_base=0x{base:08X} prio={prio}")

# 2. loopTask 活跃栈逐字解码
target = sys.argv[1] if len(sys.argv) > 1 else "loopTask"
for nmz, sp, base, prio in tasks:
    if nmz != target: continue
    print(f"\n== {nmz} 活跃栈 (SP=0x{sp:08X} 向下) ==")
    addrs, labels = [], []
    w = sp & ~3
    for k in range(0, 2048, 4):
        raw = pa_read(w + k)
        if not raw: break
        v = struct.unpack("<I", raw)[0]
        if 0x42000000 <= v < 0x42200000 or 0x40810000 <= v < 0x40830000:
            addrs.append(f"0x{v:X}")
            labels.append((w + k, v))
        if len(addrs) >= 80: break
    if not addrs:
        print("  (无代码指针)"); sys.exit(0)
    r = subprocess.run(f'"{A2L}" -pfiaC -e "{ELF}" ' + " ".join(addrs),
                       capture_output=True, text=True, shell=True)
    sym = {}
    cur = []
    for line in r.stdout.splitlines():
        if line.startswith("0x"):
            if cur: sym[cur[0].split(":")[0].strip().lower()] = cur
            cur = [line]
        elif line.strip(): cur.append(line.strip())
    if cur: sym[cur[0].split(":")[0].strip().lower()] = cur
    import re
    for (pa, v), a in zip(labels, addrs):
        s = sym.get(a.lower(), [f"0x{v:08X}: ??"])
        txt = " | ".join(s[1:]) if len(s) > 1 else s[0]
        txt = re.sub(r"C:\\Users\\Oracle.Z\\.platformio\\packages\\[^ ]*/", "", txt)
        txt = re.sub(r"/home/runner/work/esp32-arduino-lib-builder/esp32-arduino-lib-builder/esp-idf/", "", txt)
        print(f"  [0x{pa:08X}] {txt[:140]}")
