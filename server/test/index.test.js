// 单元与集成测试套件: 针对 P0/P1 代码修复项的自动化校验
//
// 原则:
//  - 服务端 (JS) 逻辑一律从 server/src/logic.js 导入真实实现, 不在测试里复制一份,
//    否则测试通过并不能保证生产代码没退化。
//  - 固件 (Arduino C++, firmware/src/main.cpp) 无法被 Node 直接 import, 因此:
//      (a) 用 Node 镜像实现描述「期望行为规格」(注释标注, 不作为真实代码覆盖);
//      (b) 追加源码契约检查, 断言 main.cpp 里这些修复确实存在 (防修复被回退)。
import assert from 'node:assert/strict';
import test from 'node:test';
import Database from 'better-sqlite3';
import { resolve, join } from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_ADMIN_TOKEN, CODE_TTL_MS, VERIFY_WINDOW_MS, VERIFY_LIMIT, VERSION_RE,
  makeIsWithinRoot, checkAdminToken, makeRegisterNonce, sweepExpired, makeVerifyLimiter,
  etagResult, redeemCode, summarizeStats, parseChannel, validateSsid,
} from '../src/logic.js';

const ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const mainCpp = readFileSync(join(ROOT, 'firmware', 'src', 'main.cpp'), 'utf-8');

// 内存库 (与生产一致的 schema 子集)
const makeDb = () => {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE codes(code TEXT PRIMARY KEY, status TEXT, verify_at INTEGER, redeem_at INTEGER, chip TEXT, remark TEXT, created_at INTEGER);
    CREATE TABLE flash_log(id INTEGER PRIMARY KEY AUTOINCREMENT, chip TEXT, code TEXT, md5 TEXT, result TEXT, ts INTEGER);
  `);
  return db;
};

// ---------------- 1. 固件 JSON / XSS: 行为规格 + 源码契约 ----------------
// 以下为「期望行为」的 Node 镜像, 用于锁定语义; 真实实现见 main.cpp, 由下方契约测试守护。
function extractJsonSpec(body, key) {
  const search = '"' + key + '"';
  const k = body.indexOf(search);
  if (k < 0) return "";
  const colon = body.indexOf(':', k + search.length);
  if (colon < 0) return "";
  let idx = colon + 1;
  while (idx < body.length && (body[idx] === ' ' || body[idx] === '\t' || body[idx] === '\r' || body[idx] === '\n')) idx++;
  if (idx >= body.length) return "";
  if (body[idx] === '"') {
    const q1 = idx;
    let q2 = q1 + 1;
    while (q2 < body.length) {
      if (body[q2] === '"' && body[q2 - 1] !== '\\') break;
      q2++;
    }
    return (q2 < body.length) ? body.substring(q1 + 1, q2) : "";
  }
  const comma = body.indexOf(',', idx);
  const brace = body.indexOf('}', idx);
  let end = (comma < 0) ? brace : (brace < 0 ? comma : Math.min(comma, brace));
  if (end < 0) end = body.length;
  return body.substring(idx, end).trim();
}

test('固件(规格): extractJson 字符串、数字与转义字符准确解析', () => {
  const body1 = '{"ssid":"Guest-WiFi","channel":6,"rssi":-65,"auth":"WPA2"}';
  assert.equal(extractJsonSpec(body1, 'ssid'), 'Guest-WiFi');
  assert.equal(extractJsonSpec(body1, 'channel'), '6');
  assert.equal(parseInt(extractJsonSpec(body1, 'channel'), 10), 6);
  assert.equal(extractJsonSpec(body1, 'rssi'), '-65');
  assert.equal(extractJsonSpec(body1, 'auth'), 'WPA2');
  assert.equal(extractJsonSpec(body1, 'notExist'), '');
  const body2 = '{\n  "cloneSsid" :  "MyAP" ,\n  "rate" : 20 \n}';
  assert.equal(extractJsonSpec(body2, 'cloneSsid'), 'MyAP');
  assert.equal(extractJsonSpec(body2, 'rate'), '20');
  const body3 = '{"ssid":"Shop\\\"Guest"}';
  assert.equal(extractJsonSpec(body3, 'ssid'), 'Shop\\\"Guest');
});

test('固件(契约): main.cpp 的 extractJson 修复未被回退', () => {
  // 旧缺陷写法: colon = k + strlen(key) + 2 (冒号位置算错)
  assert.ok(!mainCpp.includes('strlen(key) + 2'), '不得回退为旧的冒号偏移算法');
  assert.ok(mainCpp.includes("body.indexOf(':', k + search.length())"),
    'extractJson 必须精确定位冒号');
  assert.ok(mainCpp.includes('static String htmlEscape('), 'htmlEscape 必须存在');
  assert.ok(mainCpp.includes('htmlEscape(targetName)'), '门户页必须对 SSID 做 HTML 转义');
});

test('固件(契约): 120ms 扫描与内存预分配未被回退', () => {
  assert.ok(mainCpp.includes('WiFi.scanNetworks(false, true, false, 120)'), '扫描驻留应为 120ms');
  assert.ok(mainCpp.includes('json.reserve('), 'JSON 构造必须预分配');
});

// ---------------- 2. 服务端: 直接导入真实实现 ----------------
test('P0: Nonce 单一活跃性 (真实 makeRegisterNonce)', () => {
  const store = new Map();
  const registerNonce = makeRegisterNonce(store, CODE_TTL_MS);

  const code = 'ESP32-AAAA-BBBB-CCCC';
  const n1 = registerNonce(code, 'esp32');
  assert.equal(store.size, 1);
  assert.ok(store.has(n1));

  const n2 = registerNonce(code, 'esp32');
  assert.equal(store.size, 1, '一码同时仅一个活跃 nonce');
  assert.ok(!store.has(n1), '旧 nonce 应已被作废');
  assert.ok(store.has(n2), '新 nonce 应生效');

  // 不同码互不影响
  registerNonce('ESP32-OTHER-CODE', 'esp32c3');
  assert.equal(store.size, 2);
});

test('P0: 过期 nonce 清扫 (真实 sweepExpired)', () => {
  const store = new Map();
  store.set('expired', { code: 'C1', chip: null, expiresAt: 1000 });
  store.set('fresh', { code: 'C2', chip: null, expiresAt: 9000 });
  sweepExpired(store, 5000);
  assert.ok(!store.has('expired'));
  assert.ok(store.has('fresh'));
});

test('P0: 原子 Redeem 防止重放并发核销 (真实 redeemCode)', () => {
  const db = makeDb();
  const code = 'ESP32-1111-2222-3333';
  db.prepare(`INSERT INTO codes(code, status, created_at) VALUES(?, 'verified', ?)`).run(code, Date.now());

  // nonce 单次消费语义仍由路由负责, 此处验证 DB 层的原子核销不可重复
  const store = new Map();
  const nonce = 'test-nonce-123';
  store.set(nonce, { code, chip: 'esp32', expiresAt: Date.now() + 60000 });
  const consume = () => {
    const entry = store.get(nonce);
    if (!entry) return null;
    store.delete(nonce); // 立即消费
    return entry;
  };

  const first = consume();
  assert.ok(first, '首次消费应拿到 entry');
  assert.equal(redeemCode(db, first.code, first.chip, null), true, '首次核销成功');

  assert.equal(consume(), null, 'nonce 重放应立即被拒');
  // 即使绕过 nonce 直接重入, 条件更新也应拒绝二次核销
  assert.equal(redeemCode(db, code, 'esp32', null), false, '已核销码不得再次核销');

  const row = db.prepare('SELECT * FROM codes WHERE code=?').get(code);
  assert.equal(row.status, 'redeemed');
  const logs = db.prepare('SELECT * FROM flash_log WHERE code=?').all(code);
  assert.equal(logs.length, 1, '仅写入一条成功日志');
});

test('P0: 管理接口口令校验 (真实 checkAdminToken)', () => {
  assert.equal(checkAdminToken(undefined, DEFAULT_ADMIN_TOKEN), null);
  assert.deepEqual(checkAdminToken(undefined, 'wrong-token'), { status: 401, error: '管理口令错误' });
  assert.equal(checkAdminToken('my-super-secret', 'my-super-secret'), null);
  assert.deepEqual(checkAdminToken('my-super-secret', DEFAULT_ADMIN_TOKEN), { status: 401, error: '管理口令错误' });
});

test('P1: 路径越界防护与版本号白名单 (真实 makeIsWithinRoot / VERSION_RE)', () => {
  const isWithinRoot = makeIsWithinRoot(ROOT);
  assert.equal(isWithinRoot(join(ROOT, 'server/firmware/test.bin')), true);
  assert.equal(isWithinRoot(ROOT), true, '根目录本身视为边界内');
  assert.equal(isWithinRoot(resolve(ROOT, '..', 'outside.bin')), false);
  assert.equal(isWithinRoot(ROOT + '-sibling/x.bin'), false, '兄弟目录不得误放行');

  assert.equal(VERSION_RE.test('1.1.0'), true);
  assert.equal(VERSION_RE.test('v1.1.0-beta.2'), true);
  assert.equal(VERSION_RE.test('../../etc/passwd'), false);
  assert.equal(VERSION_RE.test('1.0;rm -rf'), false);
});

// ---------------- 3. 优化项: 直接导入真实实现 ----------------
test('优化: 限流 Retry-After 倒计时 (真实 makeVerifyLimiter)', () => {
  const hits = new Map();
  const check = makeVerifyLimiter(hits, VERIFY_WINDOW_MS, 3);
  const t0 = 1000000;
  assert.equal(check('1.2.3.4', t0).blocked, false);
  assert.equal(check('1.2.3.4', t0 + 1000).blocked, false);
  assert.equal(check('1.2.3.4', t0 + 2000).blocked, false);
  const r4 = check('1.2.3.4', t0 + 3000);
  assert.equal(r4.blocked, true);
  assert.equal(r4.retryAfterSec, 57);
});

test('优化: ETag / If-None-Match 304 (真实 etagResult)', () => {
  const md5 = 'a1b2c3d4e5f6';
  assert.equal(etagResult(md5, undefined).status, 200);
  assert.equal(etagResult(md5, '"different"').status, 200);
  assert.equal(etagResult(md5, `"${md5}"`).status, 304);
  assert.equal(etagResult(md5, undefined).etag, `"${md5}"`);
});

test('优化: 热点信道与 SSID 校验 (真实 parseChannel / validateSsid)', () => {
  assert.equal(parseChannel('6'), 6);
  assert.equal(parseChannel('13'), 13);
  assert.equal(parseChannel('0'), null);
  assert.equal(parseChannel('14'), null);
  assert.equal(parseChannel('abc'), null);
  assert.equal(validateSsid('My-ESP32-AP'), true);
  assert.equal(validateSsid(''), false);
  assert.equal(validateSsid('A'.repeat(32)), true);
  assert.equal(validateSsid('A'.repeat(33)), false);
});

test('优化: 管理统计聚合 (真实 summarizeStats)', () => {
  const db = makeDb();
  db.prepare(`INSERT INTO codes(code, status, created_at) VALUES('C1', 'unused', 1)`).run();
  db.prepare(`INSERT INTO codes(code, status, created_at) VALUES('C2', 'unused', 2)`).run();
  db.prepare(`INSERT INTO codes(code, status, created_at) VALUES('C3', 'verified', 3)`).run();
  db.prepare(`INSERT INTO codes(code, status, created_at) VALUES('C4', 'redeemed', 4)`).run();
  db.prepare(`INSERT INTO flash_log(chip, code, md5, result, ts) VALUES('esp32', 'C4', 'md5', 'success', 5)`).run();
  db.prepare(`INSERT INTO flash_log(chip, code, md5, result, ts) VALUES('esp32', 'C3', 'md5', 'failed', 6)`).run();

  const { ok, stats, activeNonces } = summarizeStats(db, 7);
  assert.equal(ok, true);
  assert.equal(activeNonces, 7);
  assert.equal(stats.codes.unused, 2);
  assert.equal(stats.codes.verified, 1);
  assert.equal(stats.codes.redeemed, 1);
  assert.equal(stats.codes.total, 4);
  assert.equal(stats.flashes.success, 1);
  assert.equal(stats.flashes.failed, 1);
  assert.equal(stats.flashes.total, 2);
});
