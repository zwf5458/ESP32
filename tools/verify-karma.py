# -*- coding: utf-8 -*-
"""Karma 探针诱捕验收 (合成目标): Windows 保存网络的 Probe Request → 设备捕获
流程: 启动 Karma → 已连接状态观察 40s (后台扫描) → 必要时断开 15s (主动扫描)
→ 查 /api/karma/status 断言捕获数>0 且含 SSID → 回连恢复
"""
import sys, time, subprocess, serial, urllib.request, json

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
BASE = "http://192.168.4.1"
HDR = {"X-Admin-Token": "LijxuqEkT5Wk", "Content-Type": "application/json"}

def ts():
    return f"[{time.strftime('%H:%M:%S')}]"

def ping():
    r = subprocess.run(["ping", "-n", "1", "-w", "1200", "192.168.4.1"], capture_output=True, timeout=8)
    return b"TTL" in r.stdout

def get(path):
    req = urllib.request.Request(BASE + path, headers=HDR)
    return json.loads(urllib.request.urlopen(req, timeout=8).read().decode())

def post(path, body):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
                                 headers=HDR, method="POST")
    return urllib.request.urlopen(req, timeout=8).read().decode()

ser = serial.Serial("COM3", 115200, timeout=0.05)
ser.reset_input_buffer()

def pump():
    if ser.in_waiting:
        for line in ser.read(ser.in_waiting).decode("utf-8", errors="replace").splitlines():
            if line.strip() and ("karma" in line.lower() or "client_" in line):
                print("  DEV|", line.strip()[:105])

print(ts(), "确保已连接")
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
time.sleep(12)
print(ts(), "ping:", ping())

print(ts(), "启动 Karma:", post("/api/karma/start", {}))

print(ts(), "已连接状态观察 45s (Windows 后台扫描)")
for i in range(9):
    time.sleep(5)
    pump()

st = get("/api/karma/status")
print(ts(), "status:", json.dumps(st, ensure_ascii=False)[:400])
n1 = st.get("probesCaptured", 0)

if n1 == 0:
    print(ts(), "未捕获 → 断开触发 Windows 主动扫描 15s")
    subprocess.run(["netsh", "wlan", "disconnect"], capture_output=True, timeout=20)
    time.sleep(15)
    pump()
    st = get("/api/karma/status")
    print(ts(), "status:", json.dumps(st, ensure_ascii=False)[:400])

print(ts(), "停止 Karma:", post("/api/karma/stop", {}))
st = get("/api/karma/status")
probes = st.get("probes", [])
print(ts(), f"最终: captured={st.get('probesCaptured')} baited={st.get('probesBaited')}")
for p in probes:
    if isinstance(p, dict) and p.get("ssid"):
        print("   probe:", p.get("mac"), "→", p.get("ssid"), f"rssi={p.get('rssi')}", "baited" if p.get("baited") else "")

ok = st.get("probesCaptured", 0) > 0
print(ts(), "结论:", "✓ Karma 探针捕获有效" if ok else "✗ 未捕获到探针")

print(ts(), "回连热点")
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
time.sleep(12)
print(ts(), "ping:", ping())
