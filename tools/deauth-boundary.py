# -*- coding: utf-8 -*-
"""Deauth 注入边界测试: rate=5 (200ms/帧) 连续注入, 串口监控 panic/TWDT"""
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

def pump():
    if ser.in_waiting:
        for line in ser.read(ser.in_waiting).decode("utf-8", errors="replace").splitlines():
            l = line.strip()
            if l and ("deauth" in l.lower() or "wdt" in l.lower() or "panic" in l.lower()
                      or "Guru" in l or "client_" in l or "reboot" in l.lower()):
                print("  DEV|", l[:120])

print(ts(), "确保已连接")
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
time.sleep(12)
print(ts(), "ping:", ping())

def post(path, body):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
                                 headers=HDR, method="POST")
    return urllib.request.urlopen(req, timeout=8).read().decode()

def get(path):
    req = urllib.request.Request(BASE + path, headers=HDR)
    return json.loads(urllib.request.urlopen(req, timeout=8).read().decode())

print(ts(), "启动 Deauth rate=5 (200ms/帧)")
try:
    print("  HTTP:", post("/api/deauth/start", {"bssid": "02:11:22:33:44:55", "channel": 6, "rate": 5}))
except Exception as e:
    print("  异常:", type(e).__name__)

for i in range(14):
    time.sleep(5)
    pump()
    if i in (2, 5, 8, 11):
        try:
            st = get("/api/deauth/status")
            print(ts(), "status:", json.dumps({k: st[k] for k in ("running", "count", "txOk", "txErr", "promOn")}))
        except Exception as e:
            print(ts(), "HTTP 失败:", type(e).__name__)

print(ts(), "停止")
try:
    print("  HTTP:", post("/api/deauth/stop", {}))
except Exception as e:
    print("  异常:", type(e).__name__)
