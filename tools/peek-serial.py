# -*- coding: utf-8 -*-
"""快速看串口: 打开 COM3 10 秒, 打印收到的行, 判断当前跑的是什么固件"""
import serial, time, sys

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
try:
    s = serial.Serial("COM3", 115200, timeout=0.1)
except Exception as e:
    print("COM3 打不开:", str(e)[:80])
    sys.exit(1)

buf = []
t0 = time.time()
while time.time() - t0 < 10:
    if s.in_waiting:
        buf.append(s.read(s.in_waiting).decode("utf-8", "replace"))
    time.sleep(0.4)
s.close()

lines = [l.strip() for l in "".join(buf).splitlines() if l.strip()]
print("收到", len(lines), "行:")
if lines:
    print("\n".join(l[:130] for l in lines[-14:]))
else:
    print("(静默 — 无输出)")
