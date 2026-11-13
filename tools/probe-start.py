# -*- coding: utf-8 -*-
"""纯 WiFi 复现用户场景: 点击『发起攻击』→ 热点『马上消失』到底是什么?
完全不打开 COM3 (排除串口开/关这个历史干扰源)。

唯一可靠判据 = 设备 uptime 连续性 (复位必然归零, 空口扫描有缓存不可靠):
  A 预期改名 : uptime 全程 >= U0 且递增, active=true, 空口出现克隆 SSID
  B 干净重启 : uptime 出现 << U0 的回退, active=false, 原热点 WiFi-12F9 重现
  C AP 挂死  : uptime 长时间读不到, 两个 SSID 都不出现
"""
import urllib.request, subprocess, time, json, os, sys, tempfile

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
CLONE = "ET-PROBE-7F3A"
ORIG = "WiFi-12F9"
TOKEN = os.environ.get("ADMIN_TOKEN", "admin888")
HDR = {"X-Admin-Token": TOKEN, "Content-Type": "application/json"}


def ts(): return time.strftime("%H:%M:%S")


def sh(args, timeout=12):
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout).stdout.decode("gbk", "replace")
    except Exception:
        return ""


def air():
    out = sh(["netsh", "wlan", "show", "networks"], timeout=20)
    return (CLONE in out, ORIG in out)


def info(timeout=2):
    try:
        r = urllib.request.Request("http://192.168.4.1/api/info", headers={"X-Admin-Token": TOKEN})
        return json.loads(urllib.request.urlopen(r, timeout=timeout).read().decode())
    except Exception:
        return None


def post(path, body, timeout=6):
    try:
        r = urllib.request.Request("http://192.168.4.1" + path, data=json.dumps(body).encode(),
                                   headers=HDR, method="POST")
        return urllib.request.urlopen(r, timeout=timeout).read().decode()
    except Exception as e:
        return "ERR:" + type(e).__name__


def connect(name): sh(["netsh", "wlan", "connect", f"name={name}"])


def add_open_profile(name):
    xml = ('<?xml version="1.0"?>'
           '<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">'
           f'<name>{name}</name><SSIDConfig><SSID><name>{name}</name></SSID></SSIDConfig>'
           '<connectionType>ESS</connectionType><connectionMode>manual</connectionMode>'
           '<MSM><security><authEncryption><authentication>open</authentication>'
           '<encryption>none</encryption><useOneX>false</useOneX></authEncryption></security></MSM>'
           '</WLANProfile>')
    p = os.path.join(tempfile.gettempdir(), "et_probe_profile.xml")
    open(p, "w", encoding="utf-8").write(xml)
    sh(["netsh", "wlan", "add", "profile", f"filename={p}"])
    return p


print("=" * 60)
print(ts(), "纯 WiFi 实验 — 复现『点击发起攻击, 热点马上消失』(不碰 COM3)")
print("=" * 60)

prof = add_open_profile(CLONE)
connect(ORIG)
time.sleep(8)
d0 = None
for _ in range(10):
    d0 = info(3)
    if d0: break
    connect(ORIG); time.sleep(2)
if not d0:
    print("!! 起始连不上 WiFi-12F9 的 HTTP, 环境异常, 中止")
    sys.exit(1)
U0 = d0.get("uptime", 0)
print(ts(), f"起始: uptime={U0}s ssid={d0.get('ssid')} active={d0.get('evilTwin',{}).get('active')}")

print(ts(), "设置目标:", post("/api/target", {"ssid": CLONE, "bssid": "02:1a:2b:3c:4d:5e",
                                              "channel": 6, "auth": "open"}))
t_click = time.time()
print(ts(), ">>> 点击 发起攻击:", post("/api/eviltwin/start", {}, timeout=6))

ups = []
try:
    for k in range(15):  # ~30s, 覆盖『马上消失』窗口
        time.sleep(2)
        c, o = air()
        d = info(1.5)
        if d is None:  # 管理连接断了 → 主动重连到当前在空口的那个网络再读 uptime
            connect(CLONE if c else ORIG)
            time.sleep(2)
            d = info(2)
        up = d.get("uptime") if d else None
        ssid = d.get("ssid") if d else None
        act = d.get("evilTwin", {}).get("active") if d else None
        clad = d.get("evilTwin", {}).get("apCloned") if d else None
        if up is not None: ups.append(up)
        dt = int(time.time() - t_click)
        print(f"  {ts()} t+{dt:02d}s 克隆={ '在' if c else '-'} 原={ '在' if o else '-'}"
              f" | uptime={up} ssid={ssid} active={act} apCloned={clad}")
finally:
    # 无论如何收尾恢复, 不留坏状态
    connect(ORIG)
    time.sleep(1)
    print(ts(), "停止攻击:", post("/api/eviltwin/stop", {}, timeout=6))
    sh(["netsh", "wlan", "delete", "profile", f"name={CLONE}"])
    try: os.remove(prof)
    except Exception: pass
    connect(ORIG)

min_up = min(ups) if ups else None
rebooted = (min_up is not None and U0 > 120 and min_up < U0 / 2)
print("=" * 60)
print(ts(), f"结论: 起始 uptime={U0}s, 实验中最小 uptime={min_up}s, 样本={len(ups)}")
if rebooted:
    print("  => 【B 干净重启】发起攻击触发复位 (非 panic, coredump 为空吻合), 需查复位源")
elif ups and min(ups) >= U0 - 2:
    print("  => 【A 预期改名】全程没重启! WiFi-12F9 被改名成克隆 SSID(开放), 管理连接按设计断开;")
    print("     你看到的『热点消失』= 原名消失, 实为预期行为, 不是死机。")
else:
    print("  => uptime 断点/无读数, 疑似 C(AP 挂死) 或扫描缓存, 需串口复位原因码确认")
print("=" * 60)
