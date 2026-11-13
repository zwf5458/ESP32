# -*- coding: utf-8 -*-
"""捕获 panic backtrace: 串口全程打开跨越 'PC 连入克隆热点' 时刻 (历次 panic 都发生在串口关闭时)。
t=10s 发起攻击 → t=70s 连入克隆热点 (模拟用户延迟接入) → t=150s 结束。
串口全量打印, 不做任何过滤 — panic/Guru/看门狗回溯一行都不能漏。
"""
import serial, time, subprocess, sys, json, urllib.request, threading

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
HDR = {"X-Admin-Token": "LijxuqEkT5Wk", "Content-Type": "application/json"}

def ts():
    return f"[{time.strftime('%H:%M:%S')}]"

def post(p, b, t=10):
    r = urllib.request.Request("http://192.168.4.1" + p, data=json.dumps(b).encode(),
                               headers=HDR, method="POST")
    return urllib.request.urlopen(r, timeout=t).read().decode()

def info():
    try:
        return json.loads(urllib.request.urlopen(urllib.request.Request(
            "http://192.168.4.1/api/info", headers={"X-Admin-Token": "LijxuqEkT5Wk"}), timeout=6).read())
    except Exception:
        return {}

def ping():
    r = subprocess.run(["ping", "-n", "1", "-w", "1200", "192.168.4.1"], capture_output=True, timeout=8)
    return b"TTL" in r.stdout

ser = serial.Serial("COM3", 115200, timeout=0.05)
ser.reset_input_buffer()
run = [True]
nd = [0]   # 非重复行节流: NDJSON 镜像行太吵, 只打印首个

def rd():
    while run[0]:
        if ser.in_waiting:
            for l in ser.read(ser.in_waiting).decode("utf-8", "replace").splitlines():
                l = l.strip()
                if not l: continue
                # panic/回溯/看门狗/错误 必须全量; 普通日志与其 NDJSON 镜像去重
                if any(k in l.lower() for k in ("panic", "guru", "backtrace", "abort", "assert",
                                                "wdt", "error", "e (", "w (", "reboot", "rst:")):
                    print(" DEV*|", l[:160])
                elif l.startswith("{") and '"event"' in l:
                    nd[0] += 1
                    if nd[0] % 20 == 1:
                        print(" DEVj|", l[:120])
                else:
                    print(" DEV|", l[:140])

threading.Thread(target=rd, daemon=True).start()

print(ts(), "连接原热点")
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True)
for _ in range(20):
    if ping(): break
    time.sleep(2)
i = info()
print(f"  uptime={i.get('uptime')}")
if not i.get("uptime"): raise SystemExit("未连上")

post("/api/target", {"ssid": "PanicCatch-ET", "bssid": "02:1a:2b:3c:4d:5e", "channel": 6, "auth": "open"})
post("/api/twin", {"ssid": "PanicCatch-ET", "bssid": "", "channel": 11, "fakeAp": True})
print(ts(), "发起攻击")
try:
    post("/api/eviltwin/start", {})
except Exception as e:
    print("  start 断(预期):", type(e).__name__)

print(ts(), "等待 60s (攻击空转, PC 不连接)")
time.sleep(60)

print(ts(), "连入克隆热点 (历次 panic 的触发点)")
subprocess.run(["netsh", "wlan", "connect", "name=PanicCatch-ET"], capture_output=True)
time.sleep(10)

t0 = time.time()
last_u = None
while time.time() - t0 < 80:
    i = info()
    if i.get("uptime"):
        if last_u is not None and i["uptime"] < last_u:
            print(ts(), "!!! uptime 回退 → 重启 !!!")
        last_u = i["uptime"]
        print(f"  {ts()} uptime={i['uptime']} clients={i.get('clients')}")
    else:
        print(f"  {ts()} 查询失败")
    time.sleep(12)

run[0] = False
time.sleep(0.5)
ser.close()
print(ts(), "== 结束 ==")
