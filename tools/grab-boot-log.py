# -*- coding: utf-8 -*-
"""复位后抓 12 秒完整串口输出 (应用启动日志/beacon/AP 名)"""
import serial, time, sys
sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
s = serial.Serial()
s.port, s.baudrate, s.timeout = "COM3", 115200, 0.1
s.open()
# 触发复位: 拉 DTR/RTS
s.rts = True; s.dtr = False; time.sleep(0.1); s.rts = False; time.sleep(0.1)
buf = []
t0 = time.time()
while time.time() - t0 < 12:
    if s.in_waiting:
        buf.append(s.read(s.in_waiting).decode("utf-8", "replace"))
    time.sleep(0.3)
s.close()
lines = [l.rstrip() for l in "".join(buf).splitlines() if l.strip()]
print("共 %d 行:" % len(lines))
for l in lines:
    print(" ", l[:150])
