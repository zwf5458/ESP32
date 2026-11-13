# -*- coding: utf-8 -*-
"""共存修复验证: i154 嗅探 + 客户端加入 → 固件应自动暂停嗅探让关联完成"""
import sys, time, subprocess, serial, urllib.request, json

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
BASE = "http://192.168.4.1"


def ts():
    return f"[{time.strftime('%H:%M:%S')}]"


ser = serial.Serial("COM3", 115200, timeout=0.1)
ser.reset_input_buffer()

def pump():
    out = []
    if ser.in_waiting:
        for line in ser.read(ser.in_waiting).decode("utf-8", errors="replace").splitlines():
            if line.strip():
                out.append(line.strip()[:110])
    return out

print(ts(), "等待设备启动 (20s)")
time.sleep(20)
for l in pump(): print("  DEV|", l)

print(ts(), "连接热点")
subprocess.run(["netsh", "wlan", "connect", "name=WiFi-12F9"], capture_output=True, timeout=30)
time.sleep(14)
for l in pump(): print("  DEV|", l)

r = subprocess.run(["ping", "-n", "1", "-w", "1500", "192.168.4.1"], capture_output=True, timeout=10)
print(ts(), "首次 ping:", "OK" if b"TTL" in r.stdout else "FAIL")

print(ts(), "触发 i154 帧嗅探")
req = urllib.request.Request(BASE + "/api/ieee802154/start",
                             data=json.dumps({"mode": "frames", "channel": 15, "duration": 0}).encode(),
                             headers={"X-Admin-Token": "LijxuqEkT5Wk", "Content-Type": "application/json"},
                             method="POST")
print("  HTTP:", urllib.request.urlopen(req, timeout=8).status)

# 观察 75s: 期待 被踢 → probe → [i154] 自动暂停 → AP_STA_CONNECTED → DHCP → ping 恢复
ok_ping = 0
for i in range(15):
    time.sleep(5)
    for l in pump(): print("  DEV|", l)
    if i in (8, 12, 14):
        r = subprocess.run(["ping", "-n", "1", "-w", "1500", "192.168.4.1"], capture_output=True, timeout=10)
        p = "OK" if b"TTL" in r.stdout else "FAIL"
        print(ts(), f"ping@{5*i}s:", p)
        if b"TTL" in r.stdout:
            ok_ping += 1
print(ts(), f"结论: {ok_ping}/3 次 ping 成功")
