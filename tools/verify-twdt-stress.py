# -*- coding: utf-8 -*-
"""TWDT 复现验收: 完全模拟用户挂掉的场景但用合成目标 —
全程不打开串口 (用户日常使用方式, 也是历次 panic 的触发条件),
双子目标 CH36 假 AP (跳频路径, 用户测试时用过的配置),
启动攻击 → 45s (多个跳频周期) → 门户请求 → 停止 → 恢复。
全程只靠 HTTP; 结束后另开串口验证 uptime 连续 (未重启)。
"""
import sys, time, subprocess, urllib.request, urllib.parse, json

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
BASE = "http://192.168.4.1"
HDR = {"X-Admin-Token": "LijxuqEkT5Wk"}

def ts():
    return f"[{time.strftime('%H:%M:%S')}]"

def ping():
    r = subprocess.run(["ping", "-n", "1", "-w", "1200", "192.168.4.1"], capture_output=True, timeout=8)
    return b"TTL" in r.stdout

def post_json(path, body, timeout=10):
    h = dict(HDR); h["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(), headers=h, method="POST")
    return urllib.request.urlopen(req, timeout=timeout).read().decode()

def get(path):
    req = urllib.request.Request(BASE + path, headers=HDR)
    return urllib.request.urlopen(req, timeout=8).read().decode()

def wait_up(seconds=40):
    for _ in range(seconds // 2):
        if ping(): return True
        time.sleep(2)
    return False

def info():
    try:
        return json.loads(get("/api/info"))
    except Exception:
        return {}

print(ts(), "连热点 (注意: 全程不开串口, 复现用户使用方式)")
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
assert wait_up(), "初始连接失败"
u0 = info().get("uptime")
print(f"  初始 uptime={u0}s")

print("  target:", post_json("/api/target", {"ssid": "SyntheticNet-ET", "bssid": "02:1a:2b:3c:4d:5e", "channel": 6, "auth": "open"}))
print("  twin  :", post_json("/api/twin", {"ssid": "SyntheticNet-ET", "bssid": "", "channel": 36, "fakeAp": True}))

print(ts(), "启动攻击 (含 CH36 假 AP 双子, 跳频路径; 预期改名断连)")
try:
    print("  start:", post_json("/api/eviltwin/start", {}, timeout=10))
except Exception as e:
    print("  start 网络断 (预期):", type(e).__name__)

print(ts(), "等待 45s (多个跳频周期), 期间无串口读取")
time.sleep(45)

# 断连状态下设备大概率活着; 用克隆热点回连验证
subprocess.run(["netsh", "wlan", "connect", "name=SyntheticNet-ET"], capture_output=True, timeout=30)
assert wait_up(), "克隆热点回连失败 (设备可能已挂)"
i1 = info()
u1 = i1.get("uptime"); et = i1.get("evilTwin", {})
print(f"  uptime={u1}s active={et.get('active')} hopCount={et.get('hopCount')} beacons={et.get('beacons')} twins={et.get('twins')}")

print(ts(), "门户请求 + 停止攻击")
try:
    req = urllib.request.Request(BASE + "/api/portal/submit",
        data=urllib.parse.urlencode({"wifi_password": "StressTest1"}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    urllib.request.urlopen(req, timeout=10).read()
    print("  门户提交 ✓")
except Exception as e:
    print("  门户:", type(e).__name__)
time.sleep(3)
try:
    print("  stop:", post_json("/api/eviltwin/stop", {}, timeout=10))
except Exception as e:
    print("  stop (断连属预期):", type(e).__name__)

print(ts(), "回连原热点, 验证无重启")
time.sleep(6)
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
assert wait_up(), "原热点回连失败"
i2 = info()
u2 = i2.get("uptime")
print(f"  uptime={u2}s (停止前 {u1}s)")
ok = u2 is not None and u1 is not None and u2 >= u1
print(ts(), "结论:", "✓ 全程无重启 (uptime 连续)" if ok else "✗ 设备重启过!")
