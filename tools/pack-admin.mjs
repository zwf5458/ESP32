// 工具: 把 firmware/data 下的内嵌资源压缩为 firmware/src/*.h
// 运行: node tools/pack-admin.mjs
// 注意: 构建时 platformio 的 pre 脚本 firmware/tools/embed_admin_page.py 会重新生成同一批文件,
//       它才是权威来源。Node 的 zlib(ng) 与 Python zlib 同输入产出的字节数不同, 因此本脚本
//       仅用于无 Python 环境下的本地预览; 提交前建议跑一次 Python 版本以免产生无意义 diff。
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ASSETS = [
  { src: 'admin.html', dst: 'admin_page.h', symbol: 'ADMIN_PAGE', optional: false },
  { src: 'vendor_db.js', dst: 'vendor_db.h', symbol: 'VENDOR_DB', optional: true },
];

for (const asset of ASSETS) {
  const srcPath = join(ROOT, 'firmware', 'data', asset.src);
  const dstPath = join(ROOT, 'firmware', 'src', asset.dst);
  let raw;
  try {
    raw = readFileSync(srcPath);
  } catch (e) {
    if (asset.optional) {
      console.log(`[pack-admin] 可选资源 ${asset.src} 不存在, 跳过`);
      continue;
    }
    throw e;
  }
  const compressed = zlib.deflateSync(raw, { level: 9 });

  const lines = [];
  lines.push(`// 自动生成: data/${asset.src} (zlib 压缩字节) — 改源文件后重新运行 node tools/pack-admin.mjs`);
  lines.push('#pragma once');
  lines.push('#include <pgmspace.h>');
  lines.push(`static const unsigned int ${asset.symbol}_LEN = ${compressed.length};`);
  lines.push(`static const unsigned char ${asset.symbol}[${compressed.length}] PROGMEM = {`);

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

  writeFileSync(dstPath, lines.join('\n'), 'utf-8');
  console.log(`[pack-admin] ${asset.src} (${raw.length} 字节) -> ${asset.dst} ` +
    `(deflate 压缩后 ${compressed.length} 字节, 压缩率 ${(compressed.length / raw.length * 100).toFixed(1)}%)`);
}
