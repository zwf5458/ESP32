# -*- coding: utf-8 -*-
"""列出 coredump 全部段: 段首按 TCB 解读 (sp + 任务名), 辨认哪些任务有栈、哪些没有"""
import struct, sys

sys.stdout.reconfigure(encoding="utf-8")
data = open("tools/coredump.bin", "rb").read()[0x18:]
phoff = struct.unpack_from("<I", data, 0x1C)[0]
phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
for i in range(phnum):
    o = phoff + i * phentsize
    pt, po, pv, pp, pf, pm = struct.unpack_from("<IIIIII", data, o)
    if pt == 1:
        seg = data[po:po+pf]
        name = seg[0x34:0x44].split(b"\x00")[0].decode(errors="replace")
        printable = all(32 <= b < 127 for b in name.encode() ) if name else False
        sp = struct.unpack_from("<I", seg, 0)[0]
        tag = ""
        if name and name.replace("_", "").isalnum() and len(name) <= 16:
            tag = f" TCB name={name!r} sp=0x{sp:08X}"
        print(f"pa=0x{pp:08X} size=0x{pf:X}{tag}")
