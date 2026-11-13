# -*- coding: utf-8 -*-
"""多波特率探测 + 复位抓启动输出, 判断设备当前固件"""
import serial, time, sys

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
BAUDS = [115200, 74880, 9600, 460800, 921600]
for baud in BAUDS:
    try:
        s = serial.Serial()
        s.port = "COM3"
        s.baudrate = baud
        s.timeout = 0.1
        s.open()
    except Exception as e:
        print(f"{baud}: 打不开 ({str(e)[:50]})")
        continue
    # RTS/DTR 复位进启动
    s.rts = True
    s.dtr = False
    time.sleep(0.1)
    s.rts = False
    time.sleep(0.1)
    buf = []
    t0 = time.time()
    while time.time() - t0 < 4:
        if s.in_waiting:
            buf.append(s.read(s.in_waiting).decode("utf-8", "replace"))
        time.sleep(0.2)
    s.close()
    text = "".join(buf)
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    print(f"--- {baud}: {len(lines)} 行 ---")
    for l in lines[:8]:
        print("   ", l[:120])
    if lines:
        break
