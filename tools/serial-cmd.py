# -*- coding: utf-8 -*-
"""向 ESP32-C5 发送一条串口 CLI 命令并抓取输出。
用法: python tools/serial-cmd.py txtest [秒数]

注意: 本板 RTS 接复位脚, 打开/关闭串口会触发复位 —— 会清空内存里的目标 AP、
断开 HTTP 会话。能用 HTTP 验证的场景请优先用 tools/deauth-kick-test.py。
"""
import serial, sys, time

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
CMD = sys.argv[1] if len(sys.argv) > 1 else "txtest"
DUR = float(sys.argv[2]) if len(sys.argv) > 2 else 12.0

s = serial.Serial()
s.port, s.baudrate, s.timeout = "COM3", 115200, 0.2
s.dtr = True
s.rts = True
s.open()
time.sleep(0.4)
s.reset_input_buffer()
s.write((CMD + "\n").encode())
s.flush()

buf = []
t0 = time.time()
while time.time() - t0 < DUR:
    n = s.in_waiting
    if n:
        buf.append(s.read(n).decode("utf-8", "replace"))
    time.sleep(0.15)
s.close()

out = "".join(buf)
for line in out.splitlines():
    line = line.strip()
    if line:
        print(line[:200])
print("---- 共 %d 字符 ----" % len(out))
