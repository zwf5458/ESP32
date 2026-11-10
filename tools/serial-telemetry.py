#!/usr/bin/env python3
"""
ESP32 固件 Serial JSON 遥测 · PC 命令行消费示例 (即插即用)

固件在 115200 波特率下同时输出两类行:
  - 普通文本日志 (如 "[wifi] AP 已启动 ...")
  - 以 '{' 开头的 NDJSON 遥测事件, 每行一个 JSON 对象, 例如:
      {"v":1,"ts":12345,"event":"client_join","clients":1}

本脚本读串口, 按行解析: 文本日志原样显示, JSON 事件结构化打印;
并支持只订阅特定 event、输出原始行、或导出为 NDJSON 文件。

用法:
  python3 tools/serial-telemetry.py                      # 自动探测串口
  python3 tools/serial-telemetry.py /dev/cu.usbserial-0001
  python3 tools/serial-telemetry.py --baud 115200       # 默认 115200
  python3 tools/serial-telemetry.py --event heartbeat --event client_join
  python3 tools/serial-telemetry.py --raw                # 原样输出每一行(不解析)
  python3 tools/serial-telemetry.py --save run.ndjson    # 把 JSON 事件存成 NDJSON 文件

依赖: pip install pyserial   (PlatformIO venv 通常已自带)
"""
import argparse
import json
import os
import sys
import time

# Windows 终端原生 ANSI 色彩激活
if sys.platform == "win32":
    os.system("")


def require_pyserial():
    try:
        import serial
        from serial.tools import list_ports
        return serial, list_ports
    except ImportError:
        sys.stderr.write("缺少 pyserial: 请运行  pip install pyserial\n")
        sys.exit(1)


def auto_port(list_ports):
    """优先挑常见的 USB 串口 (ESP32 / CP210x / CH340 / JTAG)"""
    prefer = ("usbserial", "usbmodem", "ACM", "USB", "COM")
    ports = list(list_ports.comports())
    if not ports:
        return None
    for p in ports:
        if any(k.lower() in (p.device + " " + (p.description or "")).lower() for k in prefer):
            return p.device
    return ports[0].device


def color_for(event):
    return {
        "boot": "\033[96m",
        "log": "\033[90m",
        "heartbeat": "\033[94m",
        "scan_result": "\033[92m",
        "client_join": "\033[93m",
        "client_leave": "\033[93m",
        "lab_state": "\033[95m",
    }.get(event, "\033[97m")


def main():
    ap = argparse.ArgumentParser(description="ESP32 Serial JSON 遥测消费端")
    ap.add_argument("port", nargs="?", help="串口设备 (省略则自动探测)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--event", action="append", default=[],
                    help="只显示指定 event (可重复); 省略则显示全部")
    ap.add_argument("--raw", action="store_true", help="原样输出每行, 不解析 JSON")
    ap.add_argument("--save", help="把解析出的 JSON 事件追加写入 NDJSON 文件")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--reconnect", action="store_true", help="串口断开后自动尝试重连 (适用于设备重启或固件重新烧录场景)")
    args = ap.parse_args()

    serial, list_ports = require_pyserial()
    out = None
    if args.save:
        out = open(args.save, "a", encoding="utf-8")

    if args.event:
        print(f"[telemetry] 仅订阅: {', '.join(args.event)}", flush=True)

    while True:
        port = args.port or auto_port(list_ports)
        if not port:
            if args.reconnect:
                sys.stderr.write("未检测到可用串口设备, 2 秒后自动重新探测...\n")
                time.sleep(2)
                continue
            sys.stderr.write("未找到串口设备, 请用参数显式指定, 如:\n"
                             "  python3 tools/serial-telemetry.py /dev/cu.usbserial-0001\n")
            sys.exit(2)

        ser = None
        try:
            print(f"[telemetry] 连接 {port} @ {args.baud}  (Ctrl-C 退出)", flush=True)
            ser = serial.Serial(port, args.baud, timeout=1)
        except Exception as e:
            sys.stderr.write(f"打不开串口 {port}: {e}\n")
            if args.reconnect:
                time.sleep(2)
                continue
            sys.exit(3)

        try:
            while True:
                try:
                    raw = ser.readline()
                except Exception as e:
                    sys.stderr.write(f"串口读取断开: {e}\n")
                    break
                if not raw:
                    continue
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if args.raw:
                    print(line, flush=True)
                    continue

                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        # 以 { 开头但不是合法 JSON (分片/损坏) → 当普通文本
                        print(line, flush=True)
                        continue
                    ev = obj.get("event", "?")
                    if args.event and ev not in args.event:
                        continue
                    if out:
                        out.write(json.dumps(obj, ensure_ascii=False) + "\n")
                        out.flush()
                    if args.no_color:
                        print(json.dumps(obj, ensure_ascii=False), flush=True)
                    else:
                        c = color_for(ev)
                        ts = obj.get("ts", 0)
                        fields = {k: v for k, v in obj.items() if k not in ("v", "ts", "event")}
                        print(f"{c}[{ts:>9} ms] {ev:<13}\033[0m "
                              f"{json.dumps(fields, ensure_ascii=False)}", flush=True)
                else:
                    # 文本日志: 有 event 过滤时默认隐藏, 否则原样显示
                    if not args.event:
                        print(line, flush=True)
        except KeyboardInterrupt:
            print("\n[telemetry] 已退出", flush=True)
            break
        finally:
            if ser:
                ser.close()

        if not args.reconnect:
            break
        print(f"[telemetry] 2 秒后尝试自动重新连接 {port} ...", flush=True)
        time.sleep(2)

    if out:
        out.close()


if __name__ == "__main__":
    main()
