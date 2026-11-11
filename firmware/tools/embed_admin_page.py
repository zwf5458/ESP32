#!/usr/bin/env python3
"""PlatformIO 预构建脚本: 把 data/admin.html 打包成 src/admin_page.h 供固件内嵌 (zlib 格式)"""
import os
import zlib

try:
    Import("env")  # noqa: F821
    PROJECT_DIR = env["PROJECT_DIR"]
except NameError:
    PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

SRC = os.path.join(PROJECT_DIR, "data", "admin.html")
DST = os.path.join(PROJECT_DIR, "src", "admin_page.h")

if os.path.exists(SRC):
    with open(SRC, "rb") as f:
        raw = f.read()
    # zlib 格式 (含 zlib 头/尾), 固件响应头标 Content-Encoding: deflate, 浏览器可解
    blob = zlib.compress(raw, 9)
    lines, chunk = [], []
    for b in blob:
        chunk.append(f"0x{b:02X}")
        if len(chunk) == 12:
            lines.append("  " + ", ".join(chunk))
            chunk = []
    if chunk:
        lines.append("  " + ", ".join(chunk))
    with open(DST, "w", encoding="utf-8", newline="\n") as f:
        f.write("// 自动生成: data/admin.html (zlib 压缩字节) — 改 HTML 后重新编译即可\n")
        f.write("#pragma once\n#include <pgmspace.h>\n")
        f.write(f"static const unsigned int ADMIN_PAGE_LEN = {len(blob)};\n")
        f.write(f"static const unsigned char ADMIN_PAGE[{len(blob)}] PROGMEM = {{\n" + ",\n".join(lines) + "\n};\n")
    print(f"[embed_admin_page] {SRC} -> {DST} ({len(blob)} bytes)")
else:
    print("[embed_admin_page] data/admin.html 不存在, 跳过")
