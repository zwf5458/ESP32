# -*- coding: utf-8 -*-
"""长时程复现: 完整模拟用户挂掉的场景 —
攻击发起后不停止运行 5 分钟, 串口全程随行 (任何 panic 的真实 backtrace 都会被捕获),
PC 挂在克隆热点上每 10s 轮询 /api/info (uptime/hopCount/beacons),
每 20s 请求一次门户页 (历次 panic 栈落点 sendPortalPage)。
双子: ch11 (2.4G 现实场景) + ch36 (5G 边界场景), 均开假 AP。
"""
import serial, time, subprocess, sys, json, urllib.request, threading

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
HDR = {"X-Admin-Token": "LijxuqEkT5Wk", "Content-Type": "application/json"}
DUR = 300

def ts():
    return f"[{time.strftime('%H:%M:%S')}]"

def post(p, b, t=10):
    r = urllib.request.Request("http://192.168.4.1" + p, data=json.dumps(b).encode(),
                               headers=HDR, method="POST")
    return urllib.request.urlopen(r, timeout=t).read().decode()

def get(p, t=8):
    req = urllib.request.Request("http://192.168.4.1" + p, headers=HDR)
    return urllib.request.urlopen(req, timeout=t).read().decode()

def info():
    try:
        return json.loads(get("/api/info"))
    except Exception:
        return {}

def ping():
    r = subprocess.run(["ping", "-n", "1", "-w", "1200", "192.168.4.1"], capture_output=True, timeout=8)
    return b"TTL" in r.stdout

def wait_up(seconds=40):
    for _ in range(seconds // 2):
        if ping(): return True
        time.sleep(2)
    return False

ser = serial.Serial("COM3", 115200, timeout=0.05)
ser.reset_input_buffer()
run = [True]
serial_events = []

def rd():
    while run[0]:
        if ser.in_waiting:
            for l in ser.read(ser.in_waiting).decode("utf-8", "replace").splitlines():
                l = l.strip()
                if not l: continue
                # 全量捕获; panic/回溯/看门狗行必须原样记录
                keep = any(k in l.lower() for k in
                           ("viltwin", "hop", "twin", "deauth", "beacon", "panic", "guru",
                            "backtrace", "wdt", "abort", "assert", "error", "双子", "portal",
                            "[ev]", "[wdt]", "channel"))
                if keep:
                    print(" DEV|", l[:150])
                    serial_events.append(l)

threading.Thread(target=rd, daemon=True).start()

print(ts(), "== 阶段1: 连接原热点, 配置合成目标 ==")
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True)
assert wait_up(), "初始连接失败"
i = info()
print(f"  uptime={i.get('uptime')} heap={i.get('heap')}")

print(post("/api/target", {"ssid": "SyntheticNet-ET", "bssid": "02:1a:2b:3c:4d:5e", "channel": 6, "auth": "open"}))
print(post("/api/twin", {"ssid": "SyntheticNet-ET", "bssid": "", "channel": 11, "fakeAp": True}))
print(post("/api/twin", {"ssid": "SyntheticNet-ET", "bssid": "", "channel": 36, "fakeAp": True}))

print(ts(), "== 阶段2: 发起攻击 (预期改名断连) ==")
try:
    print("  start:", post("/api/eviltwin/start", {})[:110])
except Exception as e:
    print("  start 网络断 (预期):", type(e).__name__)

time.sleep(6)
print(ts(), "== 阶段3: 连入克隆热点, 持续观察 5 分钟 (不停止攻击) ==")
subprocess.run(["netsh", "wlan", "connect", "name=SyntheticNet-ET"], capture_output=True)
time.sleep(8)

t0 = time.time()
last_uptime = None
panic_detected = False
n = 0
while time.time() - t0 < DUR:
    n += 1
    i = info()
    if i.get("uptime") is not None:
        et = i.get("evilTwin", {})
        print(f"  #{n} uptime={i['uptime']} active={et.get('active')} hop={et.get('hopCount')} "
              f"beacons={et.get('beacons')} hopEn={et.get('hopEnabled')} hopCur={et.get('hopCurrent')} "
              f"heap={i.get('heap')} clients={i.get('clients')}")
        if last_uptime is not None and i["uptime"] < last_uptime:
            print(ts(), "!!! uptime 回退 → 设备重启 (panic) !!!")
            panic_detected = True
        last_uptime = i["uptime"]
    else:
        print(f"  #{n} 查询失败 (HTTP 不通)")
        if not ping():
            print("    ping 也不通, 等待恢复…")
    # 周期性请求门户页 (历次 panic 栈落点)
    if n % 2 == 0:
        try:
            urllib.request.urlopen("http://192.168.4.1/portal.html", timeout=8).read()
            print("    门户页请求 ✓")
        except Exception as e:
            print("    门户页请求:", type(e).__name__)
    time.sleep(10)

run[0] = False
time.sleep(0.5)
ser.close()

final = info()
print(ts(), f"== 结论: 5分钟 {'✓ 无重启' if last_uptime and not panic_detected else '✗ 发生重启'} "
      f"(最终 uptime={final.get('uptime')}) ==")
