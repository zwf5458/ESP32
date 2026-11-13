# -*- coding: utf-8 -*-
"""死亡后验证: 1) 重开串口读 uptime/beacon (判定是否重启)  2) 读 coredump 分区 (判定是否新写)"""
import serial, time, sys, subprocess

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
CD_OFF, CD_LEN = 0xFF0000, 0x10000

def ts():
    return f"[{time.strftime('%H:%M:%S')}]"

print(ts(), "== 1) 重开串口 8s, 读 uptime/beacon ==")
s = serial.Serial("COM3", 115200, timeout=0.05)
buf = []
t0 = time.time()
while time.time() - t0 < 8:
    if s.in_waiting:
        buf.append(s.read(s.in_waiting).decode("utf-8", "replace"))
    time.sleep(0.4)
s.close()
lines = [l.strip()[:130] for l in "".join(buf).splitlines() if l.strip()]
print(f"  收到 {len(lines)} 行; 末尾 6 行:")
for l in lines[-6:]:
    print("   ", l)

print(ts(), "== 2) 读 coredump 分区 0xFF0000 ==")
subprocess.run([
    r"C:\Users\Oracle.Z\.platformio\packages\tool-esptool\esptool.exe",
    "--chip", "esp32c5", "--port", "COM3", "--baud", "921600",
    "read_flash", hex(CD_OFF), hex(CD_LEN), "tools/coredump.bin",
], capture_output=True)
data = open("tools/coredump.bin", "rb").read()
blank = all(b == 0xFF for b in data)
print(f"  全 0xFF (空白/已擦): {blank}")
if not blank:
    nz = next(i for i, b in enumerate(data) if b != 0xFF)
    print(f"  首个非 0xFF 字节偏移: 0x{nz:X}  头 32 字节: {data[nz:nz+32].hex()}")
    print("  → coredump 分区被重新写入!")
