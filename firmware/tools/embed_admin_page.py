#!/usr/bin/env python3
"""PlatformIO 预构建脚本: 把 data/ 下需要内嵌的资源压缩成 src/*.h (zlib 格式)。

当前资源:
  data/admin.html    -> src/admin_page.h (ADMIN_PAGE / ADMIN_PAGE_LEN)
  data/vendor_db.js  -> src/vendor_db.h   (VENDOR_DB  / VENDOR_DB_LEN)

zlib 格式 (含 zlib 头/尾), 固件响应头标 Content-Encoding: deflate, 浏览器可解。
"""
import os
import zlib

try:
    Import("env")  # noqa: F821
    PROJECT_DIR = env["PROJECT_DIR"]
except NameError:
    PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

DATA_DIR = os.path.join(PROJECT_DIR, "data")
SRC_DIR = os.path.join(PROJECT_DIR, "src")

# (源文件, 目标头文件, C 符号前缀, 缺失时是否报错)
ASSETS = [
    ("admin.html", "admin_page.h", "ADMIN_PAGE", True),
    ("vendor_db.js", "vendor_db.h", "VENDOR_DB", False),
]


def embed(src_name, dst_name, symbol):
    src = os.path.join(DATA_DIR, src_name)
    dst = os.path.join(SRC_DIR, dst_name)
    with open(src, "rb") as f:
        raw = f.read()
    blob = zlib.compress(raw, 9)
    lines, chunk = [], []
    for b in blob:
        chunk.append(f"0x{b:02X}")
        if len(chunk) == 12:
            lines.append("  " + ", ".join(chunk))
            chunk = []
    if chunk:
        lines.append("  " + ", ".join(chunk))
    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"// 自动生成: data/{src_name} (zlib 压缩字节) — 改源文件后重新编译即可\n")
        f.write("#pragma once\n#include <pgmspace.h>\n")
        f.write(f"static const unsigned int {symbol}_LEN = {len(blob)};\n")
        f.write(f"static const unsigned char {symbol}[{len(blob)}] PROGMEM = {{\n"
                + ",\n".join(lines) + "\n};\n")
    print(f"[embed_admin_page] data/{src_name} -> {os.path.basename(dst)} "
          f"({len(raw)} -> {len(blob)} bytes)")


for src_name, dst_name, symbol, required in ASSETS:
    if os.path.exists(os.path.join(DATA_DIR, src_name)):
        embed(src_name, dst_name, symbol)
    elif required:
        print(f"[embed_admin_page] 缺少 data/{src_name}, 跳过")
    else:
        print(f"[embed_admin_page] 可选资源 data/{src_name} 不存在, 跳过")
