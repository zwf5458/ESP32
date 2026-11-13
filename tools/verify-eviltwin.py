# -*- coding: utf-8 -*-
"""邪恶双子完整链路验收 (合成目标, 全程不碰真实网络):
串口全程打开后台读取 (防 USB CDC 背压楔死 loopTask) →
连原热点 → 设合成目标 → 启动攻击 (start 会因软 AP 改名踢连接而超时, 预期) →
连克隆热点 SyntheticNet-ET → 提交伪凭据 → 验证捕获+自动收尾 →
停止 → 恢复原热点回连验证
"""
import sys, time, subprocess, serial, urllib.request, urllib.parse, json, os, threading

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
BASE = "http://192.168.4.1"
HDR = {"X-Admin-Token": "LijxuqEkT5Wk"}
CLONE_SSID = "SyntheticNet-ET"

def ts():
    return f"[{time.strftime('%H:%M:%S')}]"

def ping():
    r = subprocess.run(["ping", "-n", "1", "-w", "1200", "192.168.4.1"], capture_output=True, timeout=8)
    return b"TTL" in r.stdout

def post_json(path, body, timeout=8):
    h = dict(HDR); h["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(), headers=h, method="POST")
    return urllib.request.urlopen(req, timeout=timeout).read().decode()

def get(path):
    req = urllib.request.Request(BASE + path, headers=HDR)
    return json.loads(urllib.request.urlopen(req, timeout=8).read().decode())

# 串口全程打开 + 后台读取 (排空 CDC, 防背压)
ser = serial.Serial("COM3", 115200, timeout=0.05)
running = [True]

def reader():
    while running[0]:
        try:
            if ser.in_waiting:
                for line in ser.read(ser.in_waiting).decode("utf-8", errors="replace").splitlines():
                    l = line.strip()
                    if l and any(k in l for k in ("eviltwin", "portal", "client_", "panic", "wdt", "AP_")):
                        print("  DEV|", l[:110])
        except Exception:
            break
        time.sleep(0.1)

threading.Thread(target=reader, daemon=True).start()

ok_conn = ok_creds = caught = ok_restore = False
try:
    print(ts(), "连接原热点, 设置合成目标")
    subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
    for _ in range(8):
        time.sleep(3)
        if ping(): break
    assert ping(), "初始连接失败"
    print("  target:", post_json("/api/target", {"ssid": CLONE_SSID, "bssid": "02:1a:2b:3c:4d:5e", "channel": 6, "auth": "open"}))

    print(ts(), "启动邪恶双子攻击 (软 AP 改名会踢掉连接, 超时属预期)")
    try:
        print("  start:", post_json("/api/eviltwin/start", {}, timeout=10))
    except Exception as e:
        print("  start 异常 (预期):", type(e).__name__)

    print(ts(), "等克隆热点广播, 连接 (开放网络)")
    time.sleep(10)
    prof = f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{CLONE_SSID}</name>
  <SSIDConfig><SSID><name>{CLONE_SSID}</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <MSM><security><authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption></security></MSM>
</WLANProfile>'''
    prof_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "et-profile.xml")
    with open(prof_path, "w", encoding="ascii") as f:
        f.write(prof)
    add = subprocess.run(["netsh", "wlan", "add", "profile", "filename=" + prof_path, "user=current"],
                         capture_output=True, timeout=20)
    addtxt = (add.stdout + add.stderr).decode("gbk", errors="replace")
    print("  add profile:", addtxt.strip()[:80])
    subprocess.run(["netsh", "wlan", "connect", "name=" + CLONE_SSID], capture_output=True, timeout=30)
    for i in range(8):
        time.sleep(4)
        if ping():
            ok_conn = True
            print(ts(), f"已连上克隆热点 (+{4*(i+1)}s) ✓")
            break
    if not ok_conn:
        print(ts(), "克隆热点连接失败 ✗")

    if ok_conn:
        print(ts(), "受害者提交伪凭据 (门户表单)")
        data = urllib.parse.urlencode({"wifi_password": "FakePass123!"}).encode()
        req = urllib.request.Request(BASE + "/api/portal/submit", data=data,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        resp = urllib.request.urlopen(req, timeout=10).read().decode()
        print("  门户响应:", "✓ 捕获页返回成功" if "凭据已同步" in resp else resp[:80])
        time.sleep(2)

        creds = get("/api/eviltwin/creds")
        et = get("/api/info").get("evilTwin", {})
        print(ts(), "creds:", json.dumps(creds, ensure_ascii=False)[:250])
        print(ts(), f"evilTwin: caught={et.get('caught')} credsCount={et.get('credsCount')}")
        ok_creds = et.get("credsCount", 0) > 0 or (isinstance(creds, dict) and (creds.get("count", 0) > 0 or bool(creds.get("creds"))))
        caught = bool(et.get("caught"))

    print(ts(), "停止攻击, 恢复原热点")
    try:
        print("  stop:", post_json("/api/eviltwin/stop", {}))
    except Exception as e:
        print("  stop 异常:", type(e).__name__)
    time.sleep(8)
    subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
    for i in range(8):
        time.sleep(4)
        if ping():
            ok_restore = True
            print(ts(), f"原热点恢复 (+{4*(i+1)}s) ✓")
            break
finally:
    running[0] = False
    time.sleep(0.3)
    ser.close()

verdict = ok_conn and ok_creds and caught and ok_restore
print(ts(), "结论:", "✓ 邪恶双子核心链路有效 (克隆热点+凭据捕获+自动收尾+恢复)"
      if verdict else f"✗ 部分: 连接={ok_conn} 凭据={ok_creds} 自动收尾={caught} 恢复={ok_restore}")
