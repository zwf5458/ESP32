# -*- coding: utf-8 -*-
"""对照实验 C: 无攻击, 纯 '串口打开→关闭' 跃迁, 扫描监控 3 分钟。
若 C 也死 → 端口关闭本身就是毒; 若 C 存活 → 需要攻击(克隆AP)与关闭的组合。
"""
import serial, time, subprocess, sys

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)

def ts():
    return f"[{time.strftime('%H:%M:%S')}]"

# 等 AP 出现
for _ in range(20):
    out = subprocess.run(["netsh", "wlan", "show", "networks"], capture_output=True, timeout=20).stdout.decode("gbk", "replace")
    if "WiFi-12F9" in out: break
    time.sleep(3)
print(ts(), "WiFi-12F9 可见, 打开串口 4 秒 (DTR 建立) 然后关闭")
s = serial.Serial("COM3", 115200, timeout=0.05)
s.read(4096)
time.sleep(4)
s.close()
print(ts(), "串口已关闭, 扫描监控 180 秒")

time.sleep(15)
t0 = time.time()
deaths = 0
prev = True
while time.time() - t0 < 180:
    out = subprocess.run(["netsh", "wlan", "show", "networks"], capture_output=True, timeout=20).stdout.decode("gbk", "replace")
    alive = "WiFi-12F9" in out
    print(f"  {ts()} AP={'在' if alive else '消失'}")
    if prev and not alive:
        deaths += 1
        print(ts(), "!!! AP 消失 !!!")
    prev = alive
    time.sleep(12)

print(ts(), f"== 实验 C 结论: 消失次数={deaths} → {'✓ 端口关闭不致死' if deaths == 0 else '✗ 端口关闭本身致死'} ==")
