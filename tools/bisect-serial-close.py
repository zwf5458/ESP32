# -*- coding: utf-8 -*-
"""二分实验: 定位 '攻击运行 + 串口关闭' 死亡的触发因子。
用法: python bisect-serial-close.py notwin|twin
流程: 连热点 → 配置 → 开串口3秒 (connected=true) → 关串口 → 发起攻击 → 关闭端口3秒再开...
关键: 死亡仅在 '端口打开过再关闭' 时发生, 所以攻击发起后再次短暂开/关端口 (模拟用户用完串口),
然后完全关闭串口, 纯 WiFi 扫描监控 4 分钟: 克隆热点消失且原热点重现 = 重启。
"""
import serial, time, subprocess, sys, json, urllib.request, threading

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
HDR = {"X-Admin-Token": "LijxuqEkT5Wk", "Content-Type": "application/json"}
MODE = sys.argv[1] if len(sys.argv) > 1 else "twin"
CLONE = "Bisect-ET" if MODE == "twin" else "Bisect-NoTwin"

def ts():
    return f"[{time.strftime('%H:%M:%S')}]"

def post(p, b, t=10):
    r = urllib.request.Request("http://192.168.4.1" + p, data=json.dumps(b).encode(),
                               headers=HDR, method="POST")
    return urllib.request.urlopen(r, timeout=t).read().decode()

def ping():
    r = subprocess.run(["ping", "-n", "1", "-w", "1200", "192.168.4.1"], capture_output=True, timeout=8)
    return b"TTL" in r.stdout

print(ts(), f"== 实验 {MODE}: 克隆热点={CLONE} ==")
ser = serial.Serial("COM3", 115200, timeout=0.05)
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True)
for _ in range(20):
    if ping(): break
    time.sleep(2)

post("/api/target", {"ssid": CLONE, "bssid": "02:1a:2b:3c:4d:5e", "channel": 6, "auth": "open"})
if MODE == "twin":
    print("  twin:", post("/api/twin", {"ssid": CLONE, "bssid": "", "channel": 11, "fakeAp": True}))

# 串口随行启动攻击 (有日志), 然后关闭串口 — 复刻 '端口开→关' 跃迁
run = [True]
def rd():
    while run[0]:
        if ser.in_waiting:
            for l in ser.read(ser.in_waiting).decode("utf-8", "replace").splitlines():
                l = l.strip()
                if l and any(k in l for k in ("[rf]", "viltwin", "[ev]", "wdt", "panic", "Guru")):
                    print(" DEV|", l[:130])
threading.Thread(target=rd, daemon=True).start()

try:
    post("/api/eviltwin/start", {})
except Exception as e:
    print("  start 断(预期):", type(e).__name__)
time.sleep(6)
ser.close()   # ← 关键: 串口关闭, connected true→false 跃迁
print(ts(), "串口已关闭, 纯扫描监控 4 分钟")

time.sleep(20)
t0 = time.time()
reboots = 0
prev_alive = True
while time.time() - t0 < 240:
    out = subprocess.run(["netsh", "wlan", "show", "networks"], capture_output=True, timeout=20).stdout.decode("gbk", "replace")
    has_clone = CLONE in out
    has_orig = "WiFi-12F9" in out
    alive = has_clone
    print(f"  {ts()} 克隆热点={'在' if has_clone else '消失'}  原热点={'在' if has_orig else '-'}")
    if prev_alive and not alive:
        reboots += 1
        print(ts(), "!!! 克隆热点消失 → 疑似重启 !!!")
    prev_alive = alive
    time.sleep(15)

print(ts(), f"== 实验 {MODE} 结论: 消失次数={reboots} → {'✓ 存活' if reboots == 0 else '✗ 死亡复现'} ==")
