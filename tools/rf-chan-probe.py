# -*- coding: utf-8 -*-
"""捕获 applyApChannel 失败的错误码: ch11 双子 + 攻击发起, 串口随行 40s"""
import serial, time, subprocess, sys, json, urllib.request, threading

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
HDR = {"X-Admin-Token": "LijxuqEkT5Wk", "Content-Type": "application/json"}

def post(p, b, t=10):
    r = urllib.request.Request("http://192.168.4.1" + p, data=json.dumps(b).encode(),
                               headers=HDR, method="POST")
    return urllib.request.urlopen(r, timeout=t).read().decode()

def ping():
    r = subprocess.run(["ping", "-n", "1", "-w", "1200", "192.168.4.1"], capture_output=True, timeout=8)
    return b"TTL" in r.stdout

ser = serial.Serial("COM3", 115200, timeout=0.05)
ser.reset_input_buffer()
run = [True]

def rd():
    while run[0]:
        if ser.in_waiting:
            for l in ser.read(ser.in_waiting).decode("utf-8", "replace").splitlines():
                l = l.strip()
                if l and any(k in l for k in ("[rf]", "切换", "双子", "viltwin", "[ev]", "wdt", "panic")):
                    print(" DEV|", l[:140])

threading.Thread(target=rd, daemon=True).start()

subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True)
for _ in range(20):
    if ping(): break
    time.sleep(2)

post("/api/target", {"ssid": "RF-Chan-Test", "bssid": "02:1a:2b:3c:4d:5e", "channel": 6, "auth": "open"})
print(post("/api/twin", {"ssid": "RF-Chan-Test", "bssid": "", "channel": 11, "fakeAp": True}))
try:
    post("/api/eviltwin/start", {})
except Exception as e:
    print("start 断(预期):", type(e).__name__)

time.sleep(40)
run[0] = False
time.sleep(0.4)
ser.close()
print("== 结束 ==")
