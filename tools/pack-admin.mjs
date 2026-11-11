// 工具: 把 firmware/data/admin.html 压缩为 firmware/src/admin_page.h
// 运行: node tools/pack-admin.mjs
// 注意: 构建时 platformio 的 pre 脚本 firmware/tools/embed_admin_page.py 会重新生成同一文件,
//       它才是权威来源。Node 的 zlib(ng) 与 Python zlib 同输入产出的字节数不同, 因此本脚本
//       仅用于无 Python 环境下的本地预览; 提交前建议跑一次 Python 版本以免产生无意义 diff。
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HTML_PATH = join(ROOT, 'firmware', 'data', 'admin.html');
const HEADER_PATH = join(ROOT, 'firmware', 'src', 'admin_page.h');

const html = readFileSync(HTML_PATH);
const compressed = zlib.deflateSync(html, { level: 9 });

const lines = [];
lines.push('// 自动生成: data/admin.html (zlib 压缩字节) — 改 HTML 后重新运行 node tools/pack-admin.mjs');
lines.push('#pragma once');
lines.push('#include <pgmspace.h>');
lines.push(`static const unsigned int ADMIN_PAGE_LEN = ${compressed.length};`);
lines.push(`static const unsigned char ADMIN_PAGE[${compressed.length}] PROGMEM = {`);

const hexBytes = [];
for (let i = 0; i < compressed.length; i++) {
  hexBytes.push('0x' + compressed[i].toString(16).toUpperCase().padStart(2, '0'));
}

const BYTES_PER_ROW = 12;
for (let i = 0; i < hexBytes.length; i += BYTES_PER_ROW) {
  const chunk = hexBytes.slice(i, i + BYTES_PER_ROW);
  lines.push('  ' + chunk.join(', ') + (i + BYTES_PER_ROW < hexBytes.length ? ',' : ''));
}
lines.push('};');
lines.push('');

writeFileSync(HEADER_PATH, lines.join('\n'), 'utf-8');
console.log(`[pack-admin] admin.html (${html.length} 字节) -> admin_page.h (deflate 压缩后 ${compressed.length} 字节, 压缩率 ${(compressed.length / html.length * 100).toFixed(1)}%)`);
