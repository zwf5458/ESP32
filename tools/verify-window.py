# -*- coding: utf-8 -*-
"""端到端用户场景: i154 嗅探导致掉线 → 等服务窗口打开 → 手动点连接 → 应立即成功 (ping+HTTP)"""
import sys, time, subprocess, serial, urllib.request, json

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
BASE = "http://192.168.4.1"
HDR = {"X-Admin-Token": "LijxuqEkT5Wk", "Content-Type": "application/json"}

def ts():
    return f"[{time.strftime('%H:%M:%S')}]"

def ping():
    r = subprocess.run(["ping", "-n", "1", "-w", "1200", "192.168.4.1"], capture_output=True, timeout=8)
    return b"TTL" in r.stdout

ser = serial.Serial("COM3", 115200, timeout=0.05)
ser.reset_input_buffer()

def pump(filt=True):
    if ser.in_waiting:
        for line in ser.read(ser.in_waiting).decode("utf-8", errors="replace").splitlines():
            if line.strip() and (not filt or "i154" in line or "[wifi]" in line or "client_" in line):
                print("  DEV|", line.strip()[:105])

print(ts(), "等待启动 15s, 连接热点")
time.sleep(15)
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
time.sleep(13)
print(ts(), "连接 ping:", ping())

req = urllib.request.Request(BASE + "/api/ieee802154/start",
                             data=json.dumps({"mode": "frames", "channel": 15, "duration": 0}).encode(),
                             headers=HDR, method="POST")
print(ts(), "触发 i154:", urllib.request.urlopen(req, timeout=8).status)

# 等待设备进入服务窗口 (嗅探 60s 后): 盯串口 "进入服务窗口"
print(ts(), "等待 62s 让服务窗口打开 (射频重启完成)")
time.sleep(62)
pump()

print(ts(), "窗口已开 → 手动点连接 (模拟用户操作)")
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
ok = False
for i in range(8):
    time.sleep(4)
    pump()
    if ping():
        ok = True
        print(ts(), f"ping 恢复 (+{4*(i+1)}s) ✓")
        break
    print(ts(), f"ping 未通 ({4*(i+1)}s)")

pump()
try:
    req = urllib.request.Request(BASE + "/api/info", headers=HDR)
    st = urllib.request.urlopen(req, timeout=6).status
    print(ts(), "HTTP 后台可达:", st)
except Exception as e:
    print(ts(), "HTTP 后台不可达:", type(e).__name__)

print(ts(), "结论:", "窗口内手动回连成功 ✓ (无需按复位)" if ok else "✗ 失败")
