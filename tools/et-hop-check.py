# -*- coding: utf-8 -*-
"""双子跳频 + panic 捕获复测: 串口全程随行, 验证 hopCount/beacons 递增, 捕获任何 panic backtrace"""
import serial, time, subprocess, sys, json, urllib.request, threading

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
HDR = {"X-Admin-Token": "LijxuqEkT5Wk", "Content-Type": "application/json"}

def post(p, b, t=10):
    r = urllib.request.Request("http://192.168.4.1" + p, data=json.dumps(b).encode(), headers=HDR, method="POST")
    return urllib.request.urlopen(r, timeout=t).read().decode()

def getinfo():
    try:
        return json.loads(urllib.request.urlopen(urllib.request.Request(
            "http://192.168.4.1/api/info", headers={"X-Admin-Token": "LijxuqEkT5Wk"}), timeout=6).read())
    except Exception:
        return {}

ser = serial.Serial("COM3", 115200, timeout=0.05)
ser.reset_input_buffer()
run = [True]

def rd():
    while run[0]:
        if ser.in_waiting:
            for l in ser.read(ser.in_waiting).decode("utf-8", "replace").splitlines():
                l = l.strip()
                if l and any(k in l for k in ("viltwin", "hop", "AP_", "deauth", "双子", "acktrace",
                                              "panic", "Guru", "wdt", "beacon] ")):
                    print(" DEV|", l[:130])

threading.Thread(target=rd, daemon=True).start()

subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True)
time.sleep(15)
i = getinfo()
print(f"预检: uptime={i.get('uptime')}")
if not i.get("uptime"):
    raise SystemExit("未连上设备")

print(post("/api/target", {"ssid": "HopTest-ET", "bssid": "02:1a:2b:3c:4d:5e", "channel": 6, "auth": "open"}))
print(post("/api/twin", {"ssid": "HopTest-ET", "bssid": "", "channel": 36, "fakeAp": True}))
try:
    print("start:", post("/api/eviltwin/start", {})[:120])
except Exception as e:
    print("start 断(预期):", type(e).__name__)

t0 = time.time()
while time.time() - t0 < 50:
    time.sleep(2)
run[0] = False
time.sleep(0.4)
ser.close()
print("监控结束 (50s)")
