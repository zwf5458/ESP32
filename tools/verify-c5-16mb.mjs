#!/usr/bin/env node
// C5 16MB 三系统离线自检脚本 (无需硬件)
// 校验分区表 / 烧录台 / 固件 / 构建脚本 / 服务端之间的偏移与约束一致性
//
// 用法: node tools/verify-c5-16mb.mjs

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

let pass = 0, fail = 0;
const failures = [];

function check(name, fn) {
  try {
    fn();
    pass++;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    fail++;
    failures.push({ name, error: e.message });
    console.log(`  ✗ ${name}`);
    console.log(`    → ${e.message}`);
  }
}

// ========== 读取关键文件 ==========
const partCsv = readFileSync(join(ROOT, 'firmware', 'partitions-16mb-triple.csv'), 'utf-8');
const ini = readFileSync(join(ROOT, 'firmware', 'platformio.ini'), 'utf-8');
const mainCpp = readFileSync(join(ROOT, 'firmware', 'src', 'main.cpp'), 'utf-8');
const appJs = readFileSync(join(ROOT, 'flasher', 'app.js'), 'utf-8');
const indexHtml = readFileSync(join(ROOT, 'flasher', 'index.html'), 'utf-8');
const adminHtml = readFileSync(join(ROOT, 'firmware', 'data', 'admin.html'), 'utf-8');
const buildSh = readFileSync(join(ROOT, 'tools', 'build-firmware.sh'), 'utf-8');
const logicJs = readFileSync(join(ROOT, 'server', 'src', 'logic.js'), 'utf-8');
const indexJs = readFileSync(join(ROOT, 'server', 'src', 'index.js'), 'utf-8');

// ========== 解析分区表 ==========
function parsePartitionTable(csv) {
  const parts = {};
  for (const line of csv.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const cols = trimmed.split(',').map(c => c.trim());
    if (cols.length < 5) continue;
    const [name, type, subtype, offsetStr, sizeStr] = cols;
    const offset = parseInt(offsetStr, 16);
    const size = parseInt(sizeStr, 16);
    parts[name] = { type, subtype, offset, size };
  }
  return parts;
}

const partitions = parsePartitionTable(partCsv);

// ========== 解析烧录台 SLOT_PARTITION_LIMITS ==========
function parseSlotLimits(js) {
  const limits = {};
  const re = /0x([0-9A-Fa-f]+):\s*\{\s*name:\s*'([^']+)',\s*maxBytes:\s*0x([0-9A-Fa-f]+)/g;
  let m;
  while ((m = re.exec(js)) !== null) {
    limits[parseInt(m[1], 16)] = { name: m[2], maxBytes: parseInt(m[3], 16) };
  }
  return limits;
}

const slotLimits = parseSlotLimits(appJs);

// ========== 解析固件 SYSTEM_SLOTS ==========
function parseSystemSlots(cpp) {
  const slots = [];
  const re = /\{\s*"(\w+)",\s*"([^"]+)",\s*"([^"]*)",\s*(\w+),\s*"(\w+)"\s*\}/g;
  let m;
  while ((m = re.exec(cpp)) !== null) {
    slots.push({
      id: m[1],
      name: m[2],
      desc: m[3],
      subtype: m[4],
      label: m[5],
    });
  }
  return slots;
}

const systemSlots = parseSystemSlots(mainCpp);

// ========== 解析烧录台 HTML select 选项 ==========
function parseFlasherSelect(html) {
  const options = [];
  const re = /<option\s+value="(0x[0-9A-Fa-f]+)"[^>]*>([^<]+)<\/option>/g;
  let m;
  while ((m = re.exec(html)) !== null) {
    options.push({ offset: parseInt(m[1], 16), text: m[2] });
  }
  return options;
}

const flasherOptions = parseFlasherSelect(indexHtml);

// ========================================================================
console.log('\n=== 1. 分区表基础校验 ===');
// ========================================================================

check('分区表包含 nvs / otadata / phy_init', () => {
  assert.ok(partitions.nvs, '缺少 nvs 分区');
  assert.ok(partitions.otadata, '缺少 otadata 分区');
  assert.ok(partitions.phy_init, '缺少 phy_init 分区');
});

check('分区表定义 ota_0 / ota_1 / ota_2', () => {
  assert.ok(partitions.ota_0, '缺少 ota_0');
  assert.ok(partitions.ota_1, '缺少 ota_1');
  assert.ok(partitions.ota_2, '缺少 ota_2');
});

check('ota_0 偏移 = 0x10000', () => {
  assert.equal(partitions.ota_0.offset, 0x10000,
    `期望 0x10000, 实际 0x${partitions.ota_0.offset.toString(16)}`);
});

check('ota_1 偏移 = 0x400000', () => {
  assert.equal(partitions.ota_1.offset, 0x400000,
    `期望 0x400000, 实际 0x${partitions.ota_1.offset.toString(16)}`);
});

check('ota_2 偏移 = 0x7F0000', () => {
  assert.equal(partitions.ota_2.offset, 0x7F0000,
    `期望 0x7F0000, 实际 0x${partitions.ota_2.offset.toString(16)}`);
});

check('三个 OTA 分区大小一致 (各 0x3F0000 = 3.9375MB)', () => {
  assert.equal(partitions.ota_0.size, 0x3F0000);
  assert.equal(partitions.ota_1.size, 0x3F0000);
  assert.equal(partitions.ota_2.size, 0x3F0000);
});

check('分区表无重叠 (ota_0 结束 <= ota_1 开始)', () => {
  const ota0End = partitions.ota_0.offset + partitions.ota_0.size;
  assert.ok(ota0End <= partitions.ota_1.offset,
    `ota_0 结束 0x${ota0End.toString(16)} > ota_1 开始 0x${partitions.ota_1.offset.toString(16)}`);
});

check('分区表无重叠 (ota_1 结束 <= ota_2 开始)', () => {
  const ota1End = partitions.ota_1.offset + partitions.ota_1.size;
  assert.ok(ota1End <= partitions.ota_2.offset,
    `ota_1 结束 0x${ota1End.toString(16)} > ota_2 开始 0x${partitions.ota_2.offset.toString(16)}`);
});

check('分区表总大小 <= 16MB', () => {
  const lastPart = Object.values(partitions).pop();
  const totalEnd = lastPart.offset + lastPart.size;
  assert.ok(totalEnd <= 0x1000000,
    `分区表总结束 0x${totalEnd.toString(16)} > 16MB (0x1000000)`);
});

check('分区表纯 ASCII (Windows PlatformIO 兼容)', () => {
  assert.ok(!/[^\x00-\x7F]/.test(partCsv),
    '分区表含非 ASCII 字符, Windows 下 PlatformIO 会 UnicodeDecodeError');
});

// ========================================================================
console.log('\n=== 2. 烧录台 SLOT_PARTITION_LIMITS 与分区表一致性 ===');
// ========================================================================

check('烧录台定义 ota_0 容量上限 = 0x3F0000', () => {
  const limit = slotLimits[0x010000];
  assert.ok(limit, '缺少 ota_0 容量上限定义');
  assert.equal(limit.maxBytes, 0x3F0000,
    `期望 0x3F0000, 实际 0x${limit.maxBytes.toString(16)}`);
});

check('烧录台定义 ota_1 容量上限 = 0x3F0000', () => {
  const limit = slotLimits[0x400000];
  assert.ok(limit, '缺少 ota_1 容量上限定义');
  assert.equal(limit.maxBytes, 0x3F0000);
});

check('烧录台定义 ota_2 容量上限 = 0x3F0000', () => {
  const limit = slotLimits[0x7F0000];
  assert.ok(limit, '缺少 ota_2 容量上限定义');
  assert.equal(limit.maxBytes, 0x3F0000);
});

check('烧录台定义整片写入上限 = 0x1000000 (16MB)', () => {
  const limit = slotLimits[0x000000];
  assert.ok(limit, '缺少整片写入上限定义');
  assert.equal(limit.maxBytes, 0x1000000);
});

check('烧录台容量上限与分区表大小一致', () => {
  for (const [name, part] of Object.entries(partitions)) {
    if (!name.startsWith('ota_')) continue;
    const limit = slotLimits[part.offset];
    assert.ok(limit, `分区 ${name} (0x${part.offset.toString(16)}) 缺少烧录台容量上限`);
    assert.equal(limit.maxBytes, part.size,
      `${name}: 分区表大小 0x${part.size.toString(16)} ≠ 烧录台上限 0x${limit.maxBytes.toString(16)}`);
  }
});

// ========================================================================
console.log('\n=== 3. 烧录台 HTML select 选项与分区表一致性 ===');
// ========================================================================

check('烧录台 select 包含 ota_0 (0x10000)', () => {
  const opt = flasherOptions.find(o => o.offset === 0x10000);
  assert.ok(opt, '缺少 ota_0 选项');
  assert.ok(opt.text.includes('ota_0') || opt.text.includes('审计'),
    `ota_0 选项文案不含 "ota_0" 或 "审计": ${opt.text}`);
});

check('烧录台 select 包含 ota_1 (0x400000)', () => {
  const opt = flasherOptions.find(o => o.offset === 0x400000);
  assert.ok(opt, '缺少 ota_1 选项');
  assert.ok(opt.text.includes('ota_1') || opt.text.includes('ESPsoup'),
    `ota_1 选项文案不含 "ota_1" 或 "ESPsoup": ${opt.text}`);
});

check('烧录台 select 包含 ota_2 (0x7F0000)', () => {
  const opt = flasherOptions.find(o => o.offset === 0x7F0000);
  assert.ok(opt, '缺少 ota_2 选项');
  assert.ok(opt.text.includes('ota_2') || opt.text.includes('Muse'),
    `ota_2 选项文案不含 "ota_2" 或 "Muse": ${opt.text}`);
});

check('烧录台 select 包含整片写入 (0x0)', () => {
  const opt = flasherOptions.find(o => o.offset === 0x0);
  assert.ok(opt, '缺少整片写入选项');
});

// ========================================================================
console.log('\n=== 4. 固件 SYSTEM_SLOTS 与分区表一致性 ===');
// ========================================================================

check('固件定义 3 个系统槽位', () => {
  assert.equal(systemSlots.length, 3, `期望 3 个槽位, 实际 ${systemSlots.length}`);
});

check('固件槽位 ID = audit / espsoup / muse', () => {
  const ids = systemSlots.map(s => s.id).sort();
  assert.deepEqual(ids, ['audit', 'espsoup', 'muse']);
});

check('固件槽位标签 = ota_0 / ota_1 / ota_2', () => {
  const labels = systemSlots.map(s => s.label).sort();
  assert.deepEqual(labels, ['ota_0', 'ota_1', 'ota_2']);
});

check('固件调用 esp_ota_set_boot_partition', () => {
  assert.ok(mainCpp.includes('esp_ota_set_boot_partition'),
    '固件未调用 esp_ota_set_boot_partition');
});

check('固件调用 esp_ota_get_running_partition', () => {
  assert.ok(mainCpp.includes('esp_ota_get_running_partition'),
    '固件未调用 esp_ota_get_running_partition');
});

check('固件实现 isSlotInstalled (0xE9 魔数检查)', () => {
  assert.ok(mainCpp.includes('isSlotInstalled'), '缺少 isSlotInstalled 函数');
  assert.ok(mainCpp.includes('0xE9'), '缺少 0xE9 魔数检查');
});

// ========================================================================
console.log('\n=== 5. PlatformIO env 配置 ===');
// ========================================================================

check('存在 [env:esp32c5_16mb]', () => {
  assert.ok(/\[env:esp32c5_16mb\]/.test(ini), '缺少 [env:esp32c5_16mb]');
});

check('esp32c5_16mb 使用 16MB 分区表', () => {
  const envMatch = /\[env:esp32c5_16mb\]([\s\S]*?)(?=\n\[|$)/.exec(ini);
  assert.ok(envMatch, '无法解析 [env:esp32c5_16mb]');
  assert.ok(envMatch[1].includes('board_build.partitions = partitions-16mb-triple.csv'),
    'esp32c5_16mb 未使用 partitions-16mb-triple.csv');
});

check('esp32c5_16mb 声明 Flash = 16MB', () => {
  const envMatch = /\[env:esp32c5_16mb\]([\s\S]*?)(?=\n\[|$)/.exec(ini);
  assert.ok(envMatch, '无法解析 [env:esp32c5_16mb]');
  assert.ok(/board_upload\.flash_size\s*=\s*16MB/.test(envMatch[1]),
    'esp32c5_16mb 未声明 board_upload.flash_size = 16MB');
});

check('esp32c5_16mb 放开体积上限 = 16777216', () => {
  const envMatch = /\[env:esp32c5_16mb\]([\s\S]*?)(?=\n\[|$)/.exec(ini);
  assert.ok(envMatch, '无法解析 [env:esp32c5_16mb]');
  assert.ok(/board_upload\.maximum_size\s*=\s*16777216/.test(envMatch[1]),
    'esp32c5_16mb 未设置 board_upload.maximum_size = 16777216');
});

check('esp32c5_16mb 继承 env:esp32c5', () => {
  const envMatch = /\[env:esp32c5_16mb\]([\s\S]*?)(?=\n\[|$)/.exec(ini);
  assert.ok(envMatch, '无法解析 [env:esp32c5_16mb]');
  assert.ok(envMatch[1].includes('extends = env:esp32c5'),
    'esp32c5_16mb 未继承 env:esp32c5');
});

check('16MB 分区表仅被 esp32c5_16mb 引用', () => {
  const refs = (ini.match(/partitions-16mb-triple\.csv/g) || []).length;
  assert.equal(refs, 1, `分区表被引用 ${refs} 次, 期望 1 次 (仅 esp32c5_16mb)`);
});

// ========================================================================
console.log('\n=== 6. 构建脚本集成 ===');
// ========================================================================

check('构建脚本 CHIPS 包含 esp32c5_16mb', () => {
  assert.ok(/CHIPS=\([^)]*\besp32c5_16mb\b/.test(buildSh),
    '构建脚本 CHIPS 数组缺少 esp32c5_16mb');
});

check('esp32c5_16mb bootloader 偏移 = 0x2000', () => {
  assert.ok(/esp32c5_16mb\)\s*BL_OFFSET="0x2000"/.test(buildSh),
    'esp32c5_16mb bootloader 偏移不是 0x2000');
});

check('esp32c5_16mb esptool chip = esp32c5', () => {
  assert.ok(/esp32c5_16mb\)\s+BL_OFFSET="0x2000";\s*ESPTOOL_CHIP="esp32c5"/.test(buildSh),
    'esp32c5_16mb esptool chip 不是 esp32c5');
});

// ========================================================================
console.log('\n=== 7. 服务端芯片注册 ===');
// ========================================================================

check('CHIP_ALIASES 包含 esp32c5_16mb', () => {
  assert.ok(logicJs.includes("'esp32c5_16mb'") || logicJs.includes('"esp32c5_16mb"'),
    'CHIP_ALIASES 缺少 esp32c5_16mb');
});

check('BOOTLOADER_OFFSET 包含 esp32c5_16mb = 0x2000', () => {
  assert.ok(/esp32c5_16mb:\s*0x2000/.test(indexJs),
    'BOOTLOADER_OFFSET 缺少 esp32c5_16mb: 0x2000');
});

// ========================================================================
console.log('\n=== 8. 烧录台芯片显示 ===');
// ========================================================================

check("chipDisplayName('esp32c5_16mb') 返回 'ESP32-C5 (16MB 三系统)'", () => {
  assert.ok(appJs.includes("key === 'esp32c5_16mb'"),
    "烧录台缺少 key === 'esp32c5_16mb' 判断");
  assert.ok(appJs.includes("'ESP32-C5 (16MB 三系统)'") || appJs.includes('"ESP32-C5 (16MB 三系统)"'),
    "烧录台缺少 'ESP32-C5 (16MB 三系统)' 显示名");
});

check('自动识别不覆盖手动选择的同芯片变体', () => {
  assert.ok(/startsWith\(detected \+ '_'\)/.test(appJs),
    '烧录台自动识别可能覆盖手动选择的 16MB 变体');
});

// ========================================================================
console.log('\n=== 9. Web 后台多系统卡片 ===');
// ========================================================================

check('admin.html 包含 bootCard', () => {
  assert.ok(adminHtml.includes('id="bootCard"'), 'admin.html 缺少 id="bootCard"');
});

check('admin.html 包含 loadBootSlots 函数', () => {
  assert.ok(adminHtml.includes('loadBootSlots'), 'admin.html 缺少 loadBootSlots 函数');
});

check('admin.html 包含 doSwitchBoot 函数', () => {
  assert.ok(adminHtml.includes('doSwitchBoot'), 'admin.html 缺少 doSwitchBoot 函数');
});

check('admin.html 调用 /api/system/boot', () => {
  assert.ok(adminHtml.includes('/api/system/boot'), 'admin.html 未调用 /api/system/boot');
});

// ========================================================================
console.log('\n=== 10. 串口 CLI 命令 ===');
// ========================================================================

check('固件实现 handleSerialCli', () => {
  assert.ok(mainCpp.includes('handleSerialCli'), '固件缺少 handleSerialCli');
});

check('串口 CLI 支持 boot 命令', () => {
  assert.ok(mainCpp.includes('cmd == "boot"') || mainCpp.includes('cmd == "boot status"'),
    '串口 CLI 缺少 boot 命令');
});

check('串口 CLI 支持 boot <target> 命令', () => {
  assert.ok(mainCpp.includes('cmd.startsWith("boot ")'),
    '串口 CLI 缺少 boot <target> 命令');
});

check('串口 CLI 支持 reboot 命令', () => {
  assert.ok(mainCpp.includes('cmd == "reboot"'),
    '串口 CLI 缺少 reboot 命令');
});

check('串口 CLI 支持 info 命令', () => {
  assert.ok(mainCpp.includes('cmd == "info"'),
    '串口 CLI 缺少 info 命令');
});

// ========================================================================
console.log('\n=== 11. 契约测试覆盖 ===');
// ========================================================================

const testJs = readFileSync(join(ROOT, 'server', 'test', 'index.test.js'), 'utf-8');

check('契约测试验证分区表偏移', () => {
  assert.ok(testJs.includes('0x400000') && testJs.includes('0x7F0000'),
    '契约测试未验证 ota_1/ota_2 偏移');
});

check('契约测试验证 SLOT_PARTITION_LIMITS', () => {
  assert.ok(testJs.includes('SLOT_PARTITION_LIMITS'),
    '契约测试未验证 SLOT_PARTITION_LIMITS');
});

check('契约测试验证 esp32c5_16mb env', () => {
  assert.ok(testJs.includes('esp32c5_16mb'),
    '契约测试未验证 esp32c5_16mb');
});

check('契约测试验证构建脚本集成', () => {
  assert.ok(testJs.includes('build-firmware.sh'),
    '契约测试未验证构建脚本');
});

// ========================================================================
// 汇总
// ========================================================================

console.log('\n' + '='.repeat(60));
console.log(`自检完成: ${pass} 通过, ${fail} 失败`);
console.log('='.repeat(60));

if (fail > 0) {
  console.log('\n失败项:');
  for (const f of failures) {
    console.log(`  ✗ ${f.name}`);
    console.log(`    ${f.error}`);
  }
  process.exit(1);
} else {
  console.log('\n✓ 所有检查通过！16MB 三系统实现一致性验证完成。');
  console.log('\n下一步: 按 tools/c5-16mb-verify-checklist.md 进行真机验收。');
  process.exit(0);
}
