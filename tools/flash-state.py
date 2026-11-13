# -*- coding: utf-8 -*-
"""读取并解析设备分区表 / otadata, 验证 CRC 算法, 供切换启动分区用。
用法: python tools/flash-state.py [fix]
  fix: 生成 tools/otadata-fix.bin (选 ota_0 / audit), 供 esptool 写入 0xD000
"""
import os, sys, struct, zlib

sys.stdout.reconfigure(encoding="utf-8")
T = r"C:\Users\Oracle.Z\AppData\Local\Temp\opencode"

# ---- 1. 分区表 ----
try:
    pt = open(os.path.join(T, "ptable.bin"), "rb").read()
except FileNotFoundError:
    pt = b""
print("== 设备分区表 (0x8000) ==")
for i in range(0, len(pt), 32):
    e = pt[i:i + 32]
    if len(e) < 32 or e[:2] != b"\xaa\x50":
        continue
    typ, subt = e[2], e[3]
    off, size = struct.unpack_from("<II", e, 4)
    name = e[12:28].split(b"\x00")[0].decode(errors="replace")
    print("  %-10s type=%d sub=0x%02X off=0x%X size=0x%X" % (name, typ, subt, off, size))

# ---- 2. otadata ----
d = open(os.path.join(T, "otadata.bin"), "rb").read()
print("\n== otadata 两个扇区 ==")

def crc_variants(raw28, seq4):
    out = {}
    out["zlib(28,init0)"] = zlib.crc32(raw28) & 0xFFFFFFFF
    out["zlib(28,init~0)"] = zlib.crc32(raw28, 0xFFFFFFFF) & 0xFFFFFFFF
    out["zlib(4,init0)"] = zlib.crc32(seq4) & 0xFFFFFFFF
    out["zlib(4,init~0)"] = zlib.crc32(seq4, 0xFFFFFFFF) & 0xFFFFFFFF
    out["zlib(24,init0)"] = zlib.crc32(raw28[:24]) & 0xFFFFFFFF
    return out

for sec in range(2):
    e = d[sec * 0x1000: sec * 0x1000 + 32]
    if e == b"\xff" * 32:
        print("  sector%d: 全 0xFF (空)" % sec)
        continue
    seq = struct.unpack_from("<I", e, 0)[0]
    state = struct.unpack_from("<I", e, 0x18)[0]
    crc = struct.unpack_from("<I", e, 0x1C)[0]
    print("  sector%d: ota_seq=%d (0x%X)  ota_state=%d  crc=0x%08X" % (sec, seq, seq, state, crc))
    for k, v in crc_variants(e[:28], e[:4]).items():
        mark = "  <== 匹配" if v == crc else ""
        print("      %-20s = 0x%08X%s" % (k, v, mark))
    slot = (seq - 1) % 3 if seq != 0xFFFFFFFF else None
    print("      → 启动槽位: ota_%d %s" % (slot, {0: "audit(WiFi)", 1: "espsoup", 2: "muse"}.get(slot, "")) if slot is not None else "      → 未定义")

# ---- 3. 生成 fix ----
if len(sys.argv) > 1 and sys.argv[1] == "fix":
    # 目标: ota_0 (audit). seq 需 > 现有最大 seq 且 (seq-1)%3==0 → 取 4 (现有最大 3)
    SEQ = 4
    entry = struct.pack("<I", SEQ) + b"\xff" * 20 + struct.pack("<I", 2)  # ota_state=ESP_OTA_IMG_VALID
    crc = zlib.crc32(entry) & 0xFFFFFFFF
    entry += struct.pack("<I", crc)
    print("\n== 生成 otadata-fix.bin: ota_seq=%d (→ ota_0/audit), state=2, crc=0x%08X ==" % (SEQ, crc))
    print("   entry:", entry.hex(" "))
    # sector0 = 新有效条目, sector1 = 全 0xFF (无效) → 唯一有效条目决定启动
    fix = bytearray(b"\xff" * 0x2000)
    fix[0:32] = entry
    open(os.path.join(os.path.dirname(__file__), "..", "tools", "otadata-fix.bin"), "wb").write(fix)
    # 同时写到工程 tools/ 便于 esptool 引用
    open(r"E:\code\ESP32\tools\otadata-fix.bin", "wb").write(fix)
    print("   已写 tools/otadata-fix.bin (%d 字节)" % len(fix))
