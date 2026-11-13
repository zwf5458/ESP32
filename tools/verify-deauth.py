# -*- coding: utf-8 -*-
"""Deauth 验收 (两阶段, 全合成):
阶段1 机制: 假 BSSID 注入 → frameCount 增长 + txOk + 无崩溃
阶段2 真实效果: 目标=本机 AP (自打) → Windows 被踢 (device client_leave + PC 断网)
      → 串口 deauth 停止 → 回连恢复
"""
import sys, time, subprocess, serial, urllib.request, json

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
BASE = "http://192.168.4.1"
HDR = {"X-Admin-Token": "LijxuqEkT5Wk", "Content-Type": "application/json"}
AP_MAC = "14:c1:9f:8a:12:f9"

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

def serial_cmd(cmd, wait=4):
    global ser
    ser.close()   # 释放 COM3, 避免句柄占用
    ser = serial.Serial("COM3", 115200, timeout=0.1)
    ser.reset_input_buffer()
    ser.write((cmd + "\r\n").encode())
    time.sleep(wait)
    out = ser.read(ser.in_waiting or 1).decode("utf-8", errors="replace")
    return out

def pump():
    if ser.in_waiting:
        for line in ser.read(ser.in_waiting).decode("utf-8", errors="replace").splitlines():
            if line.strip() and ("deauth" in line.lower() or "client_" in line):
                print("  DEV|", line.strip()[:105])

ser = serial.Serial("COM3", 115200, timeout=0.05)
ser.reset_input_buffer()

print(ts(), "等待启动 15s, 连接热点")
time.sleep(15)
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
time.sleep(12)
assert ping(), "初始连接失败"
print(ts(), "ping OK, 开始阶段1")

# ---- 阶段 1: 机制验证 (假 BSSID) ----
print(ts(), "阶段1: 启动 Deauth → 假 BSSID 02:11:22:33:44:55 ch6 rate=20")
print("  HTTP:", post("/api/deauth/start", {"bssid": "02:11:22:33:44:55", "channel": 6, "rate": 20}))
time.sleep(6)
pump()
st = get("/api/deauth/status")
print(ts(), "status:", json.dumps({k: st[k] for k in st if k in ("running", "count", "txOk", "lastTxErr", "txChannel")}))
c1 = st.get("count", 0)
time.sleep(4)
st = get("/api/deauth/status")
c2 = st.get("count", 0)
print("  HTTP:", post("/api/deauth/stop", {}))
st = get("/api/deauth/status")
print(ts(), f"阶段1结论: count {c1}→{c2} (速率≈{(c2-c1)/4:.0f}帧/s), {'✓ 帧注入机制有效' if c2 > c1 and c1 > 0 else '✗ 异常'}")

# ---- 阶段 2: 真实效果 (自打: 目标=本机 AP) ----
print(ts(), f"阶段2: 启动 Deauth → 本机 AP {AP_MAC} ch6 (受害者=本 PC 链路)")
try:
    print("  HTTP:", post("/api/deauth/start", {"bssid": AP_MAC, "channel": 6, "rate": 5}))
except Exception as e:
    print("  启动响应异常(可能已被踢):", type(e).__name__)

kicked = False
for i in range(6):
    time.sleep(3)
    pump()
    if not ping():
        kicked = True
        print(ts(), f"PC 被踢 (+{3*(i+1)}s) ✓")
        break
if not kicked:
    print(ts(), "PC 未被踢 ✗")

print(ts(), "串口 deauth 命令停止注入")
print("  ", serial_cmd("deauth", wait=4).strip()[:120].replace("\n", " | "))

print(ts(), "回连恢复")
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
ok = False
for i in range(6):
    time.sleep(4)
    if ping():
        ok = True
        print(ts(), f"回连成功 (+{4*(i+1)}s) ✓")
        break
try:
    st = get("/api/deauth/status")
    print(ts(), "最终 status:", json.dumps({k: st[k] for k in st if k in ("running", "count", "txOk", "lastTxErr")}))
except Exception as e:
    print(ts(), "HTTP 不可达:", type(e).__name__)

verdict = (kicked and ok)
print(ts(), "结论:", "✓ Deauth 真实帧注入有效且可恢复" if verdict else "✗ 需人工检查")
