#!/usr/bin/env node
// 生成 vendor_db.js：IEEE OUI 厂商名 + Bluetooth SIG Company ID / Service UUID 名称。
//
// 数据只来自公开注册表，不复制任何第三方项目代码：
//   - IEEE OUI/MA-L 公开注册表（事实性数据）
//   - Bluetooth SIG Assigned Numbers（Company Identifiers / Service UUIDs）
//
// 用法:
//   node tools/gen-vendor-tables.mjs --src <目录>            # 读取本地缓存并生成
//   node tools/gen-vendor-tables.mjs --src <目录> --check    # 校验已提交文件是否与源一致
//   node tools/gen-vendor-tables.mjs --src <目录> --fetch    # 目录为空时自动下载源文件
//   node tools/gen-vendor-tables.mjs --src <目录> --stats    # 只打印选表统计
//
// 默认输出 firmware/data/vendor_db.js（提交到仓库）。生成物由固件构建脚本压缩内嵌为
// src/vendor_db.h，再由 GET /vendor-db.js 提供给后台页面。

import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_SRC = join(ROOT, 'tools', 'vendor-src');
const DEFAULT_OUT = join(ROOT, 'firmware', 'data', 'vendor_db.js');

const SOURCES = {
  oui: {
    file: 'oui.csv',
    url: 'https://standards-oui.ieee.org/oui/oui.csv',
    label: 'IEEE OUI (oui.csv)',
  },
  company: {
    file: 'company_identifiers.yaml',
    url: 'https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml',
    label: 'Bluetooth SIG company_identifiers.yaml',
  },
  service: {
    file: 'service_uuids.yaml',
    url: 'https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/uuids/service_uuids.yaml',
    label: 'Bluetooth SIG service_uuids.yaml',
  },
};

// devClass 下标必须与 firmware/src/main.cpp 的 BleDevClass 一致。
// UI 只按整数取文案；改文案不需要改固件。
const DEV_CLASSES = [
  '未知',
  'AirTag / Find My',
  'iBeacon',
  'Eddystone',
  'BTHome',
  '小米 / MiBeacon',
  'Govee',
  'Ruuvi',
  'Fast Pair',
  'Remote ID',
];

// OUI 选表规则：先按常见 AP / 路由器 / IoT / 芯片厂商取，配额用完再按科技类关键词补足。
// 只影响“显示厂商名”的覆盖率，不影响任何解析逻辑。
const OUI_RULES = [
  { kw: 'tp-link', quota: 20 },
  { kw: 'ubiquiti', quota: 20 },
  { kw: 'mikrotik', quota: 20 },
  { kw: 'cisco', quota: 20 },
  { kw: 'huawei', quota: 20 },
  { kw: 'netgear', quota: 16 },
  { kw: 'zte', quota: 16 },
  { kw: 'd-link', quota: 14 },
  { kw: 'asustek', quota: 14 },
  { kw: 'aruba', quota: 14 },
  { kw: 'h3c', quota: 14 },
  { kw: 'ruckus', quota: 12 },
  { kw: 'fiberhome', quota: 12 },
  { kw: 'nokia', quota: 12 },
  { kw: 'ruijie', quota: 10 },
  { kw: 'tenda', quota: 10 },
  { kw: 'motorola', quota: 8 },
  { kw: 'ericsson', quota: 8 },
  { kw: 'commscope', quota: 6 },
  { kw: 'extreme networks', quota: 4 },
  { kw: 'apple', quota: 16 },
  { kw: 'samsung', quota: 12 },
  { kw: 'xiaomi', quota: 16 },
  { kw: 'espressif', quota: 16 },
  { kw: 'tuya', quota: 10 },
  { kw: 'govee', quota: 4 },
  { kw: 'ruuvi', quota: 2 },
  { kw: 'tile', quota: 3 },
  { kw: 'google', quota: 12 },
  { kw: 'amazon', quota: 10 },
  { kw: 'sonos', quota: 6 },
  { kw: 'philips', quota: 6 },
  { kw: 'belkin', quota: 4 },
  { kw: 'linksys', quota: 6 },
  { kw: 'eero', quota: 6 },
  { kw: 'roku', quota: 4 },
  { kw: 'ring', quota: 4 },
  { kw: 'intel', quota: 10 },
  { kw: 'qualcomm', quota: 6 },
  { kw: 'broadcom', quota: 6 },
  { kw: 'mediatek', quota: 6 },
  { kw: 'realtek', quota: 6 },
  { kw: 'texas instruments', quota: 8 },
  { kw: 'nordic', quota: 4 },
  { kw: 'silicon lab', quota: 8 },
  { kw: 'murata', quota: 8 },
  { kw: 'azurewave', quota: 8 },
  { kw: 'hon hai', quota: 10 },
  { kw: 'liteon', quota: 6 },
  { kw: 'wistron', quota: 4 },
  { kw: 'compal', quota: 4 },
  { kw: 'quanta', quota: 4 },
  { kw: 'pegatron', quota: 4 },
  { kw: 'inventec', quota: 3 },
  { kw: 'hikvision', quota: 10 },
  { kw: 'dahua', quota: 6 },
  { kw: 'axis', quota: 4 },
  { kw: 'reolink', quota: 2 },
  { kw: 'uniview', quota: 4 },
  { kw: 'ezviz', quota: 3 },
];

const FILL_KEYWORDS = [
  'wireless', 'network', 'technolog', 'electronic', 'communication',
  'semiconductor', 'computer', 'digital', 'system', 'device', 'smart',
];

// Company ID 选表规则：先保证常见品牌与芯片厂商，剩余按 ID 从小到大补齐
// （低 ID 多为早期注册的成熟公司）。
const COMPANY_RULES = [
  { kw: 'apple', quota: 3 },
  { kw: 'samsung', quota: 3 },
  { kw: 'huawei', quota: 3 },
  { kw: 'xiaomi', quota: 3 },
  { kw: 'huami', quota: 3 },
  { kw: 'google', quota: 3 },
  { kw: 'microsoft', quota: 3 },
  { kw: 'amazon', quota: 3 },
  { kw: 'sony', quota: 3 },
  { kw: 'bose', quota: 3 },
  { kw: 'harman', quota: 3 },
  { kw: 'garmin', quota: 3 },
  { kw: 'fitbit', quota: 3 },
  { kw: 'tile', quota: 3 },
  { kw: 'ruuvi', quota: 3 },
  { kw: 'govee', quota: 3 },
  { kw: 'tuya', quota: 3 },
  { kw: 'espressif', quota: 3 },
  { kw: 'nordic', quota: 3 },
  { kw: 'texas instruments', quota: 3 },
  { kw: 'intel', quota: 3 },
  { kw: 'broadcom', quota: 3 },
  { kw: 'qualcomm', quota: 3 },
  { kw: 'realtek', quota: 3 },
  { kw: 'mediatek', quota: 3 },
  { kw: 'murata', quota: 3 },
  { kw: 'silicon lab', quota: 3 },
  { kw: 'dialog', quota: 3 },
  { kw: 'nxp', quota: 3 },
  { kw: 'st micro', quota: 3 },
  { kw: 'bosch', quota: 3 },
  { kw: 'beken', quota: 3 },
  { kw: 'telink', quota: 3 },
  { kw: 'logitech', quota: 3 },
  { kw: 'razer', quota: 3 },
  { kw: 'nintendo', quota: 3 },
  { kw: 'sonos', quota: 3 },
  { kw: 'philips', quota: 3 },
  { kw: 'signify', quota: 3 },
  { kw: 'lg electronics', quota: 3 },
  { kw: 'motorola', quota: 3 },
  { kw: 'oneplus', quota: 3 },
  { kw: 'oppo', quota: 3 },
  { kw: 'vivo', quota: 3 },
  { kw: 'anker', quota: 3 },
  { kw: 'belkin', quota: 3 },
  { kw: 'dell', quota: 3 },
  { kw: 'hewlett', quota: 3 },
  { kw: 'lenovo', quota: 3 },
  { kw: 'asustek', quota: 3 },
  { kw: 'acer', quota: 3 },
  { kw: 'toshiba', quota: 3 },
  { kw: 'panasonic', quota: 3 },
  { kw: 'honeywell', quota: 3 },
  { kw: 'siemens', quota: 3 },
  { kw: 'schneider', quota: 3 },
];

// Bluetooth SIG 的 service_uuids.yaml 只含 adopted 16-bit 服务；成员/生态常用 UUID
// (Eddystone、BTHome、Fast Pair、Remote ID 等) 需按公开规范补充，否则 UI 只能显示十六进制。
const SERVICE_EXTRA = {
  0xFEAA: 'Eddystone',
  0xFCD2: 'BTHome',
  0xFE95: 'Xiaomi / MiBeacon',
  0xFE2C: 'Fast Pair',
  0xFFFA: 'ASTM Remote ID',
  0xFD6F: 'Exposure Notification',
  0xFE59: 'Nordic DFU',
  0xFE9F: 'Google',
};

function parseArgs(argv) {
  const opts = {
    src: DEFAULT_SRC,
    out: DEFAULT_OUT,
    check: false,
    fetch: false,
    stats: false,
    ouiLimit: 512,
    companyLimit: 256,
    serviceLimit: 128,
    maxName: 24,
    date: new Date().toISOString().slice(0, 10),
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--src') opts.src = resolve(argv[++i]);
    else if (a === '--out') opts.out = resolve(argv[++i]);
    else if (a === '--check') opts.check = true;
    else if (a === '--fetch') opts.fetch = true;
    else if (a === '--stats') opts.stats = true;
    else if (a === '--date') opts.date = argv[++i];
    else if (a === '--oui-limit') opts.ouiLimit = parseInt(argv[++i], 10);
    else if (a === '--company-limit') opts.companyLimit = parseInt(argv[++i], 10);
    else if (a === '--service-limit') opts.serviceLimit = parseInt(argv[++i], 10);
    else if (a === '--max-name') opts.maxName = parseInt(argv[++i], 10);
    else if (a === '--help' || a === '-h') {
      printHelp();
      process.exit(0);
    } else {
      throw new Error(`未知参数: ${a}`);
    }
  }
  return opts;
}

function printHelp() {
  console.log(`生成 firmware/data/vendor_db.js

  --src <dir>            源文件目录 (默认 tools/vendor-src)
  --out <file>           输出文件 (默认 firmware/data/vendor_db.js)
  --check                只校验已生成文件是否与源一致
  --fetch                --src 缺少源文件时自动下载
  --stats                只打印选表统计，不写文件
  --oui-limit <n>        OUI 条目上限 (默认 512)
  --company-limit <n>    Company ID 条目上限 (默认 256)
  --service-limit <n>    Service UUID 条目上限 (默认 128)
  --max-name <n>         厂商名截断长度 (默认 24)
  --date <YYYY-MM-DD>    写入生成日期 (默认今天)
`);
}

async function fetchSources(dir) {
  mkdirSync(dir, { recursive: true });
  for (const [key, spec] of Object.entries(SOURCES)) {
    const dst = join(dir, spec.file);
    if (existsSync(dst)) continue;
    console.log(`[fetch] ${spec.url} -> ${dst}`);
    const res = await fetch(spec.url, { redirect: 'follow' });
    if (!res.ok) throw new Error(`下载失败 ${spec.url}: HTTP ${res.status}`);
    writeFileSync(dst, Buffer.from(await res.arrayBuffer()));
  }
}

function cleanName(s, maxLen) {
  let out = String(s || '').replace(/\s+/g, ' ').trim();
  if (out.length > maxLen) out = out.slice(0, maxLen).trimEnd();
  return out;
}

function parseOui(file, maxName) {
  const text = readFileSync(file, 'utf8');
  const lines = text.split(/\r?\n/);
  const rows = [];
  const seen = new Set();
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    // Registry,Assignment,"Organization Name","Organization Address"
    const m = line.match(/^([^,]+),([0-9A-Fa-f]{6}),(?:"([^"]*)"|([^,]*))/);
    if (!m) continue;
    const oui = m[2].toUpperCase();
    if (seen.has(oui)) continue;
    const org = cleanName(m[3] || m[4], maxName);
    if (!org) continue;
    seen.add(oui);
    rows.push({ oui, org, lower: org.toLowerCase() });
  }
  return rows;
}

function pickOui(rows, limit) {
  const picked = [];
  const used = new Set();
  for (const rule of OUI_RULES) {
    let n = 0;
    for (const row of rows) {
      if (n >= rule.quota || picked.length >= limit) break;
      if (used.has(row.oui)) continue;
      if (row.lower.includes(rule.kw)) {
        used.add(row.oui);
        picked.push(row);
        n++;
      }
    }
  }
  if (picked.length < limit) {
    for (const row of rows) {
      if (picked.length >= limit) break;
      if (used.has(row.oui)) continue;
      if (FILL_KEYWORDS.some(kw => row.lower.includes(kw))) {
        used.add(row.oui);
        picked.push(row);
      }
    }
  }
  picked.sort((a, b) => a.oui.localeCompare(b.oui));
  return picked;
}

function parseCompanies(file, maxName) {
  const text = readFileSync(file, 'utf8');
  const rows = [];
  const seen = new Set();
  const re = /-\s*value:\s*(0x[0-9A-Fa-f]+)\s*\r?\n\s*name:\s*(?:'([^']*)'|"([^"]*)"|([^\r\n]*))/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const value = parseInt(m[1], 16);
    if (!Number.isFinite(value) || seen.has(value)) continue;
    const name = cleanName(m[2] || m[3] || m[4], maxName);
    if (!name) continue;
    seen.add(value);
    rows.push({ value, name, lower: name.toLowerCase() });
  }
  return rows;
}

function pickCompanies(rows, limit) {
  const picked = [];
  const used = new Set();
  for (const rule of COMPANY_RULES) {
    let n = 0;
    for (const row of rows) {
      if (n >= rule.quota || picked.length >= limit) break;
      if (used.has(row.value)) continue;
      if (row.lower.includes(rule.kw)) {
        used.add(row.value);
        picked.push(row);
        n++;
      }
    }
  }
  if (picked.length < limit) {
    const rest = rows.filter(r => !used.has(r.value)).sort((a, b) => a.value - b.value);
    for (const row of rest) {
      if (picked.length >= limit) break;
      used.add(row.value);
      picked.push(row);
    }
  }
  picked.sort((a, b) => a.value - b.value);
  return picked;
}

function parseServices(file, maxName) {
  const text = readFileSync(file, 'utf8');
  const rows = [];
  const seen = new Set();
  const re = /-\s*uuid:\s*0x([0-9A-Fa-f]+)\s*\r?\n\s*name:\s*(?:'([^']*)'|"([^"]*)"|([^\r\n]*))/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const value = parseInt(m[1], 16);
    if (!Number.isFinite(value) || seen.has(value)) continue;
    const name = cleanName(m[2] || m[3] || m[4], maxName);
    if (!name) continue;
    seen.add(value);
    rows.push({ value, name });
  }
  for (const [value, name] of Object.entries(SERVICE_EXTRA)) {
    const n = Number(value);
    if (!seen.has(n)) {
      seen.add(n);
      rows.push({ value: n, name: cleanName(name, maxName) });
    }
  }
  rows.sort((a, b) => a.value - b.value);
  return rows;
}

function compactMap(entries) {
  return entries.map(([k, v]) => `${JSON.stringify(k)}:${JSON.stringify(v)}`).join(',');
}

function buildFile(opts, data) {
  const lines = [];
  lines.push('/* 自动生成，请勿手改。');
  lines.push(' * 数据来源: IEEE OUI 公开注册表 + Bluetooth SIG Assigned Numbers（事实性数据）。');
  lines.push(' * 生成脚本: node tools/gen-vendor-tables.mjs --src <目录>');
  lines.push(` * 生成日期: ${opts.date}`);
  lines.push(` * 条目数: oui=${data.oui.length} company=${data.company.length} service=${data.service.length}`);
  lines.push(' * 许可: 仅汇总公开注册数据；不含第三方代码。详见 THIRD_PARTY.md。');
  lines.push(' */');
  lines.push('window.VENDOR_DB = {');
  lines.push('  version: 1,');
  lines.push(`  generatedAt: ${JSON.stringify(opts.date)},`);
  lines.push('  classes: [');
  for (const c of DEV_CLASSES) lines.push(`    ${JSON.stringify(c)},`);
  lines.push('  ],');
  lines.push(`  oui: {${compactMap(data.oui.map(r => [r.oui, r.org]))}},`);
  lines.push(`  company: {${compactMap(data.company.map(r => [String(r.value), r.name]))}},`);
  lines.push(`  service: {${compactMap(data.service.map(r => [String(r.value), r.name]))}},`);
  lines.push('};');
  lines.push('');
  return lines.join('\n');
}

function stripVolatile(text) {
  return text
    .replace(/^ \* 生成日期: .*$/m, ' * 生成日期: <date>')
    .replace(/^  generatedAt: .*$/m, '  generatedAt: <date>')
    .replace(/\r\n/g, '\n');
}

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.fetch) await fetchSources(opts.src);

  const paths = {
    oui: join(opts.src, SOURCES.oui.file),
    company: join(opts.src, SOURCES.company.file),
    service: join(opts.src, SOURCES.service.file),
  };
  for (const [key, p] of Object.entries(paths)) {
    if (!existsSync(p)) {
      throw new Error(`缺少 ${SOURCES[key].label}: ${p}\n` +
        `请先下载，或加 --fetch 自动获取。`);
    }
  }

  const oui = pickOui(parseOui(paths.oui, opts.maxName), opts.ouiLimit);
  const company = pickCompanies(parseCompanies(paths.company, opts.maxName), opts.companyLimit);
  const service = parseServices(paths.service, opts.maxName).slice(0, opts.serviceLimit);
  const content = buildFile(opts, { oui, company, service });

  if (opts.stats) {
    console.log(`[stats] oui=${oui.length} company=${company.length} service=${service.length} ` +
      `raw=${Buffer.byteLength(content)}B`);
    return;
  }

  if (opts.check) {
    if (!existsSync(opts.out)) throw new Error(`输出文件不存在: ${opts.out}`);
    const current = readFileSync(opts.out, 'utf8');
    if (stripVolatile(current) !== stripVolatile(content)) {
      console.error(`[check] 不一致: ${opts.out} 需要重新生成`);
      process.exit(1);
    }
    console.log(`[check] 一致: ${opts.out} (oui=${oui.length} company=${company.length} service=${service.length})`);
    return;
  }

  mkdirSync(dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, content, 'utf8');
  const bytes = Buffer.byteLength(content);
  console.log(`[gen-vendor] ${opts.out}`);
  console.log(`[gen-vendor] oui=${oui.length} company=${company.length} service=${service.length} ` +
    `raw=${bytes}B (${(bytes / 1024).toFixed(1)}KB)`);
}

main().catch(err => {
  console.error(`[gen-vendor] ${err.message}`);
  process.exit(1);
});
