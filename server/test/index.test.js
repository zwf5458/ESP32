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
import { inflateSync, inflateRawSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_ADMIN_TOKEN, CODE_TTL_MS, VERIFY_WINDOW_MS, VERIFY_LIMIT, VERSION_RE,
  makeIsWithinRoot, checkAdminToken, resolveClientIp, makeRegisterNonce, sweepExpired, makeVerifyLimiter,
  etagResult, redeemCode, summarizeStats, parseChannel, validateSsid,
} from '../src/logic.js';
import {
  aesCmac, buildEapolM2, crackHandshake, deriveKck, derivePmkid, derivePtk,
  eapolKeyMic, EAPOL_KEY_MIC_OFFSET, MIC_LEN, parseM2, pbkdf2Sha1, verifyM2Mic,
} from '../src/wpa.js';

const ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const mainCpp = readFileSync(join(ROOT, 'firmware', 'src', 'main.cpp'), 'utf-8');
// 官方 aircrack-ng 单元测试向量 (tools/fetch-wpa-vectors.mjs 抓取), 离线可用
const wpaVectors = JSON.parse(
  readFileSync(join(ROOT, 'server', 'test', 'fixtures', 'wpa-vectors.json'), 'utf-8'),
);
const hex = (s) => Buffer.from(s, 'hex');

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

test('固件(契约): Deauther 为真实帧注入而非纯计数', () => {
  assert.ok(mainCpp.includes('esp_wifi_80211_tx(WIFI_IF_AP'), '必须经 AP 接口真实注入 802.11 帧');
  assert.ok(mainCpp.includes('f[0] = 0xC0'), '必须构建 0x00c0 Deauthentication 管理帧');
  assert.ok(mainCpp.includes('#include "esp_wifi.h"'), '必须引入 esp_wifi.h');
  // frameCount 只在 TX 成功后累加 (不允许回退为无条件 ++)
  assert.ok(!/sDeauth\.lastTxTime = now;\s*\n\s*sDeauth\.frameCount\+\+/.test(mainCpp),
    '不得回退为无发送的纯计数');
});

test('固件(契约): Deauther 启动前自动对齐目标信道且停止时恢复', () => {
  assert.ok(mainCpp.includes('esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE)'),
    '必须以 esp_wifi_set_channel 临时切换 AP 信道 (IDF4/IDF5 兼容签名)');
  assert.ok(mainCpp.includes('applyApChannel(sDeauth.targetChannel)'), '启动必须尝试切到目标信道');
  assert.ok(mainCpp.includes('applyApChannel(sDeauth.restoreChannel)'), '停止必须恢复配置信道');
  assert.ok(!mainCpp.includes('sPrefs.putUChar("channel", apChannelActive'),
    '临时切换不得写入 NVS 配置');
});

test('固件(契约): 握手包为真实 promiscuous 抓包而非定时器模拟', () => {
  assert.ok(mainCpp.includes('esp_wifi_set_promiscuous(true)'), '必须真正开启混杂模式收包');
  assert.ok(mainCpp.includes('esp_wifi_set_promiscuous_rx_cb(onPromiscuousFrame)'), '必须注册空口回调');
  assert.ok(mainCpp.includes('handleEapolFrame(f, len)'), '统一回调必须把数据帧交给 EAPOL 解析');
  assert.ok(mainCpp.includes('WIFI_PROMIS_FILTER_MASK_DATA'), 'EAPOL 走数据帧, 过滤必须是 DATA');
  assert.ok(mainCpp.includes('0x88, 0x8E'), '必须按 LLC/SNAP 的 0x888E 定位 EAPOL');
  assert.ok(mainCpp.includes('memcmp(ap, sHandshake.targetBssid, 6)'),
    '必须只接收选中目标 BSSID 的握手帧');
  // 旧实现按时间戳伪造 M1..M4
  assert.ok(!mainCpp.includes('dt > 800 && !sHandshake.m1'), '不得回退为定时器伪造握手状态');
  assert.ok(!mainCpp.includes('dt > 5000 && !sHandshake.m4'), '不得回退为定时器伪造握手状态');
});

test('固件(契约): 板载跑包为真实 PBKDF2 + PTK + MIC 校验', () => {
  assert.ok(mainCpp.includes('#include "mbedtls/md.h"'), '必须用 mbedtls 做 HMAC/PBKDF2');
  assert.ok(mainCpp.includes('for (int i = 1; i < 4096; i++)'), 'PBKDF2 必须是 4096 轮迭代');
  assert.ok(mainCpp.includes('mbedtls_md_hmac(md, pmk, 32, msg, 100, ptk + i * 20)'),
    'PTK 必须由 PRF-512 派生');
  assert.ok(mainCpp.includes('memset(frame + 81, 0, 16)'), 'MIC 字段 (偏移 81, 16 字节) 必须置零');
  assert.ok(mainCpp.includes('WIFI_WEAK_DICT[sHandshake.crackProgress]'), '必须遍历内置弱口令字典');
  assert.ok(mainCpp.includes('memcmp(mic, sHandshake.eapol + 81, 16) == 0'), '必须与捕获帧的 MIC 比对');
  // 旧实现直接写死命中结果
  assert.ok(!mainCpp.includes('crackedPass = "88888888"'), '不得回退为写死命中口令');
});

test('固件(契约): PMF 网络拒绝板载跑包并可导出握手材料', () => {
  assert.ok(mainCpp.includes('sHandshake.unsupported'), 'keyver 3 必须标记 unsupported');
  assert.ok(mainCpp.includes('/api/handshake/dump'), '必须提供握手材料导出接口');
  assert.ok(mainCpp.includes('hexBytes(sHandshake.anonce, 32)'), '导出必须含 ANonce');
  assert.ok(mainCpp.includes('hexBytes(sHandshake.eapol, sHandshake.eapolLen)'), '导出必须含完整 M2');
  assert.ok(mainCpp.includes('sHandshake.captured'), '跑包前必须要求 M1+M2 已捕获');
});

test('服务端(契约): /api/wpa/crack 走真实跑包引擎且需管理口令', () => {
  const indexJs = readFileSync(join(ROOT, 'server', 'src', 'index.js'), 'utf-8');
  assert.ok(indexJs.includes("app.post('/api/wpa/crack', requireAdmin"), '跑包接口必须鉴权');
  assert.ok(indexJs.includes('crackHandshake({'), '必须调用真实跑包实现');
  assert.ok(indexJs.includes("'server', 'data', 'weak-passwords.txt'"), '必须使用内置字典');
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

// ---------------- 4. WPA 握手包跑包引擎 (真实 wpa.js) ----------------
// 全部断言都以 aircrack-ng 官方单元测试向量为准: 若算法 (PRF / KDF / MIC) 被改错,
// 这些用例必然失败, 因此它们同时充当「不得回退为伪算法」的守护。
test('WPA(规格): 官方向量 — PBKDF2 PMK 与 SHA1 PRF 派生 PTK', () => {
  const v = wpaVectors.harkonen;
  const parts = { aa: hex(v.bssid), spa: hex(v.stmac), anonce: hex(v.anonce), snonce: hex(v.snonce) };
  // 该向量的 PMK 是直接给定的 (WPA 测试数据), 不是 PBKDF2 结果
  const ptk = derivePtk({ pmk: hex(v.pmk), ...parts, keyver: 2 });
  assert.equal(ptk.length, 80, 'WPA/WPA2 的 PTK 为 80 字节 (KCK 16 + KEK 16 + TK 48)');
  assert.equal(ptk.toString('hex'), v.expectedPtk, 'PRF-512 结果必须与 aircrack-ng 一致');
});

test('WPA(规格): 官方向量 — keyver 1 用 HMAC-MD5, keyver 2 用 HMAC-SHA1', () => {
  const v = wpaVectors.harkonen;
  const ptk = derivePtk({
    pmk: hex(v.pmk),
    aa: hex(v.bssid), spa: hex(v.stmac), anonce: hex(v.anonce), snonce: hex(v.snonce),
    keyver: 2,
  });
  const kck = ptk.subarray(0, 16);
  const eapol = hex(v.eapol);
  assert.equal(eapol.length, v.eapolSize);
  assert.equal(eapolKeyMic({ kck, eapol, keyver: 1 }).toString('hex'), v.expectedMicV1);
  assert.equal(eapolKeyMic({ kck, eapol, keyver: 2 }).toString('hex'), v.expectedMicV2);
});

test('WPA2-PMF(规格): 官方向量 — PBKDF2 + 802.11 KDF + AES-CMAC', () => {
  const v = wpaVectors.neheb;
  assert.equal(pbkdf2Sha1(v.passphrase, v.essid).toString('hex'), v.expectedPmk,
    'PMK = PBKDF2-HMAC-SHA1(passphrase, ESSID, 4096, 32)');
  const parts = { aa: hex(v.bssid), spa: hex(v.stmac), anonce: hex(v.anonce), snonce: hex(v.snonce) };
  const kck = deriveKck({ pmk: hex(v.expectedPmk), ...parts, keyver: 3 });
  assert.equal(kck.length, 32, 'PMF/WPA3 的 KCK 为 32 字节');
  assert.equal(kck.toString('hex'), v.expectedPtk, 'KDF 输出必须与 aircrack-ng 一致');
  assert.equal(eapolKeyMic({ kck, eapol: hex(v.eapol), keyver: 3 }).toString('hex'), v.expectedMic,
    'keyver 3 的 MIC 是 AES-CMAC (RFC 4493)');
});

test('WPA(规格): AES-CMAC 通过 RFC 4493 四个标准向量', () => {
  const key = hex('2b7e151628aed2a6abf7158809cf4f3c');
  const msg = hex(
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51' +
    '30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  );
  const cases = [
    [0, 'bb1d6929e95937287fa37d129b756746'],
    [16, '070a16b46b4d4144f79bdd9dd04a287c'],
    [40, 'dfa66747de9ae63030ca32611497c827'],
    [64, '51f0bebf7e3b9d92fc49741779363cfe'],
  ];
  for (const [len, expected] of cases) {
    assert.equal(aesCmac(key, msg.subarray(0, len)).toString('hex'), expected, `CMAC(${len}B)`);
  }
});

test('WPA(规格): PMKID 与帧解析 (MIC 固定在第 81 字节)', () => {
  const v = wpaVectors.harkonen;
  const pmkid = derivePmkid({ pmk: hex(v.pmk), aa: hex(v.bssid), spa: hex(v.stmac) });
  assert.equal(pmkid.length, 16);
  assert.equal(EAPOL_KEY_MIC_OFFSET, 81);
  assert.equal(MIC_LEN, 16);

  const frame = buildEapolM2({ snonce: Buffer.alloc(32, 1), keyver: 2 });
  const parsed = parseM2(frame);
  assert.equal(parsed.keyver, 2);
  assert.equal(parsed.snonce.toString('hex'), '01'.repeat(32));
  assert.equal(parsed.replay, 3);
  assert.equal(frame.length, 121, 'RSN ie 22 字节 → EAPOL-Key 帧共 121 字节');
});

test('WPA(规格): verifyM2Mic 只认匹配的 KCK 与 keyver', () => {
  const v = wpaVectors.neheb;
  const parts = { aa: hex(v.bssid), spa: hex(v.stmac), anonce: hex(v.anonce), snonce: hex(v.snonce) };
  const kck = deriveKck({ pmk: hex(v.expectedPmk), ...parts, keyver: 3 });
  // 上游向量把 MIC 字段置零, 先按真实帧封装后再校验
  const sealed = Buffer.from(hex(v.eapol));
  hex(v.expectedMic).copy(sealed, EAPOL_KEY_MIC_OFFSET);
  assert.equal(verifyM2Mic({ kck, eapol: sealed, keyver: 3 }), true);
  assert.equal(verifyM2Mic({ kck, eapol: sealed, keyver: 2 }), false, 'keyver 不符必须失败');
  assert.equal(verifyM2Mic({ kck: Buffer.alloc(32), eapol: sealed, keyver: 3 }), false,
    '错误 KCK 必须失败');
});

test('WPA(规格): 跑包命中真实字典下标, 未命中返回 -1', () => {
  const v = wpaVectors.neheb;
  const sealed = Buffer.from(hex(v.eapol));
  hex(v.expectedMic).copy(sealed, EAPOL_KEY_MIC_OFFSET);
  const base = { essid: v.essid, eapol: sealed, anonce: hex(v.anonce), aa: hex(v.bssid), spa: hex(v.stmac) };

  const hit = crackHandshake({ ...base, candidates: ['nope', v.passphrase, '12345678'] });
  assert.deepEqual(hit, { index: 1, candidate: v.passphrase, attempts: 2, keyver: 3 });

  const miss = crackHandshake({ ...base, candidates: ['nope', 'still-nope'] });
  assert.equal(miss.index, -1);
  assert.equal(miss.candidate, null);
  assert.equal(miss.attempts, 2);

  // 命中后立即停止, 不再尝试后续候选
  const early = crackHandshake({ ...base, candidates: [v.passphrase, '12345678', 'x'] });
  assert.equal(early.attempts, 1);
});

test('WPA(契约): 内置弱口令字典与固件头文件同序同量', () => {
  const txt = readFileSync(join(ROOT, 'server', 'data', 'weak-passwords.txt'), 'utf-8')
    .split(/\r?\n/).filter((l) => l.length > 0);
  const header = readFileSync(join(ROOT, 'firmware', 'src', 'wifi_weak_dict.h'), 'utf-8');
  const entries = [...header.matchAll(/^\s{2}"([^"]*)",?\s*$/gm)].map((m) => m[1]);

  assert.equal(txt.length, 7153, '字典条数必须与文档/固件声明的 7,153 一致');
  assert.equal(entries.length, txt.length, '头文件条目数必须与 txt 一致');
  assert.deepEqual(entries, txt, '两个文件必须同序 (固件跑包依赖同一顺序)');
  assert.equal(Number(header.match(/WIFI_WEAK_DICT_COUNT = (\d+)/)[1]), txt.length);
  assert.equal(Number(header.match(/WIFI_WEAK_DICT\[(\d+)\]/)[1]), txt.length);

  // 演示密码置顶, 保证教学时立刻命中
  assert.deepEqual(txt.slice(0, 3), ['00000000', '88888888', '12345678']);
  // WPA 口令合法区间: 8..63 字节
  for (const p of txt) {
    const len = Buffer.byteLength(p, 'utf8');
    assert.ok(len >= 8 && len <= 63, `口令长度越界: ${p}`);
  }
  assert.equal(new Set(txt).size, txt.length, '字典不得有重复项');
});

test('WPA(契约): 用内置字典跑通端到端 (演示密码命中)', () => {
  const dict = readFileSync(join(ROOT, 'server', 'data', 'weak-passwords.txt'), 'utf-8')
    .split(/\r?\n/).filter((l) => l.length > 0);
  const essid = 'esp32-c5-lab';
  const snonce = Buffer.from('11'.repeat(32), 'hex');
  const anonce = Buffer.from('22'.repeat(32), 'hex');
  const aa = hex('aabbccddeeff');
  const spa = hex('001122334455');

  for (const demo of ['00000000', '12345678']) {
    const keyver = 2;
    const kck = deriveKck({ pmk: pbkdf2Sha1(demo, essid), aa, spa, anonce, snonce, keyver });
    const frame = buildEapolM2({ snonce, keyver, kck });
    const result = crackHandshake({ essid, candidates: dict, eapol: frame, anonce, aa, spa });
    assert.equal(result.candidate, demo);
    assert.equal(dict[result.index], demo);
    assert.equal(result.attempts, result.index + 1);
  }
});

// ---------------- 5. 本轮修复: 安全加固 / 工程闭环 ----------------
test('P1: 限流客户端 IP 默认不可被 XFF 伪造 (真实 resolveClientIp)', () => {
  const headers = {
    forwardedFor: '9.9.9.9, 8.8.8.8',
    realIp: '7.7.7.7',
    remoteAddress: '::ffff:127.0.0.1',
  };
  assert.equal(resolveClientIp(headers), '::ffff:127.0.0.1', '默认必须忽略所有转发头');
  assert.equal(resolveClientIp(headers, true), '8.8.8.8',
    '可信代理模式取链尾, 而非客户端可伪造的链首');
  assert.equal(resolveClientIp({ realIp: '7.7.7.7', remoteAddress: '10.0.0.1' }, true), '7.7.7.7');
  assert.equal(resolveClientIp({ forwardedFor: '', remoteAddress: '' }, true), 'local');
  assert.equal(resolveClientIp(), 'local');
});

test('P1: 管理口令为常量时间比较且空值被拒 (真实 checkAdminToken)', () => {
  assert.equal(checkAdminToken('s3cret', 's3cret'), null);
  for (const bad of [undefined, null, '', 's3cre', 's3creT', DEFAULT_ADMIN_TOKEN]) {
    assert.equal(checkAdminToken('s3cret', bad)?.status, 401);
  }
  assert.equal(checkAdminToken(undefined, DEFAULT_ADMIN_TOKEN), null);
  const logicJs = readFileSync(join(ROOT, 'server', 'src', 'logic.js'), 'utf-8');
  assert.ok(logicJs.includes('crypto.timingSafeEqual('), '必须使用定长摘要的常量时间比较');
  assert.ok(!logicJs.includes('headerToken !== expected'), '不得回退为普通字符串比较');
});

test('固件(契约): 后台初始口令一机一密且不经遥测', () => {
  assert.ok(mainCpp.includes('#include "esp_random.h"'), '必须使用硬件 TRNG');
  assert.ok(mainCpp.includes('makeRandomAdminToken()'), '初始口令必须随机生成');
  assert.ok(mainCpp.includes('sPrefs.putString("adminToken", sAdminToken)'), '必须持久化到 NVS');
  assert.ok(mainCpp.includes('sPrefs.putBool("tokenChanged", true)'), '改密后必须标记已修改');
  assert.ok(mainCpp.includes('mustChangeToken'), '/api/info 必须暴露首次改密标志');
  assert.ok(mainCpp.includes('tokenEquals('), '口令比较必须走常量时间实现');
  assert.ok(!mainCpp.includes('ADMIN_TOKEN_DEFAULT'), '不得再使用全局静态默认口令');
  assert.ok(!/log\([^\n]*出厂默认口令/.test(mainCpp), '不得把初始口令写进 log()/遥测');
  assert.ok(mainCpp.includes('Serial.println("[admin]   " + sAdminToken)'),
    '初始口令只经物理串口直出一次');
});

test('服务端(契约): verify 限流不直接采信 XFF, 注册注释与实现一致', () => {
  const indexJs = readFileSync(join(ROOT, 'server', 'src', 'index.js'), 'utf-8');
  assert.ok(indexJs.includes('const ip = clientIp(c);'));
  assert.ok(indexJs.includes('getConnInfo(c)?.remote?.address'), '必须取 TCP 对端地址');
  assert.ok(!indexJs.includes("const ip = c.req.header('x-forwarded-for')"), '不得回退为直读 XFF');
  assert.ok(!indexJs.includes('二进制直接上传'), '注册接口注释不得声称支持二进制直传');
});

test('后台(契约): 一次导航只渲染一次且首次登录引导改密', () => {
  const html = readFileSync(join(ROOT, 'firmware', 'data', 'admin.html'), 'utf-8');
  assert.ok(html.includes('let lastRoutedPage'), '必须有路由去重状态');
  assert.ok(html.includes('if (p === lastRoutedPage) return;'), 'hashchange 必须跳过 go() 自己触发的那次');
  assert.ok(html.includes("mustChangeToken ? 'cfg'"), '首次登录必须落到配置页');
  assert.ok(html.includes('id="tokenNotice"'), '配置页必须有改密提示条');
});

test('烧录台(契约): 下载镜像后校验 manifest md5 / size', () => {
  const appJs = readFileSync(join(ROOT, 'flasher', 'app.js'), 'utf-8');
  assert.ok(appJs.includes('CryptoJS.MD5(CryptoJS.enc.Latin1.parse(bstr))'), '必须算下载镜像的 MD5');
  assert.ok(appJs.includes('if (actual !== expected)'), '必须与 manifest.md5 比对');
  assert.ok(appJs.includes('镜像 MD5 不一致'), '不一致必须抛错阻止烧录');
  assert.ok(appJs.includes('u8.length !== fw.size'), '必须同时校验镜像大小');
  assert.ok(appJs.includes('fileArray: [{ data: image, address: 0 }]'),
    'esptool-js 0.7.x 的 writeFlash 必须传 Uint8Array (字符串入参已废弃)');
});

test('烧录台(契约): 整片 Flash 备份走本地固定版本依赖', () => {
  const appJs = readFileSync(join(ROOT, 'flasher', 'app.js'), 'utf-8');
  const html = readFileSync(join(ROOT, 'flasher', 'index.html'), 'utf-8');
  assert.ok(appJs.includes('detectFlashSize()'), '备份容量必须按 Flash ID 实测, 不能按镜像大小');
  assert.ok(appJs.includes('readFlash(off, n'), '必须调用 readFlash 分块读回整片');
  assert.ok(appJs.includes('URL.createObjectURL'), '读回后必须触发浏览器下载');
  assert.ok(html.includes('id="btnBackup"'), '页面必须有「备份固件」按钮');
  assert.ok(html.includes('id="btnCustomFlash"') && html.includes('id="customSlotSelect"'),
    '页面必须有多系统/外部固件刷写入口');
  assert.ok(appJs.includes('customSlotSelect') && appJs.includes('0x7F0000'),
    '必须支持按 ota_2/ota_1 分区偏移写入外部固件 (如 Muse / ESPsoup)');
  assert.ok(appJs.includes('import { ESPLoader, Transport } from "./vendor/esptool-js-0.7.1.js"'),
    'esptool-js 必须用本地 0.7.x (0.5.x 无 C5 目标与读 Flash 能力)');
  assert.ok(html.includes('/flasher/vendor/crypto-js-4.2.0.js'), 'crypto-js 必须用本地 UMD 构建');
  assert.ok(!appJs.includes('unpkg.com') && !html.includes('unpkg.com'),
    '前端不得依赖公网 CDN (离线/内网也要能烧录)');
});

test('工程闭环(契约): admin_page.h 内嵌页与 admin.html 完全同步', () => {
  const html = readFileSync(join(ROOT, 'firmware', 'data', 'admin.html'));
  const header = readFileSync(join(ROOT, 'firmware', 'src', 'admin_page.h'), 'utf-8');
  const lenMatch = header.match(/ADMIN_PAGE_LEN\s*=\s*(\d+)/);
  assert.ok(lenMatch, '头文件必须声明 ADMIN_PAGE_LEN');
  const bytes = [...header.matchAll(/0x([0-9A-Fa-f]{2})/g)].map((m) => parseInt(m[1], 16));
  assert.equal(bytes.length, Number(lenMatch[1]), '压缩字节数必须与声明长度一致');
  const blob = Buffer.from(bytes);
  let inflated;
  try { inflated = inflateSync(blob); }       // PlatformIO pre 脚本 (Python zlib.compress)
  catch { inflated = inflateRawSync(blob); }  // 兼容 node tools/pack-admin.mjs 的 raw deflate
  assert.ok(inflated.equals(html),
    '内嵌压缩流解压后必须逐字节等于 admin.html; 改了 HTML 请重新编译固件或运行 npm run pack-admin');
});

test('后台(契约): 克隆 SSID 可显式覆盖且留空回退主目标', () => {
  const html = readFileSync(join(ROOT, 'firmware', 'data', 'admin.html'), 'utf-8');
  assert.ok(html.includes('id="etCloneSsid"'), '邪恶双子页必须有克隆 SSID 输入框');
  assert.ok(html.includes('state.etCloneSsid'), '输入草稿必须在页面重建时保留');
  assert.ok(!html.includes("const cloneSsid = '';"), '不得再把 cloneSsid 写死为空串');
  assert.ok(mainCpp.includes('sEvilTwin.cloneSsid = ssid.length() ? ssid : sTarget.ssid'),
    '留空必须回退主目标 SSID, 不能沿用上次的自定义名');
  assert.ok(mainCpp.includes('克隆 SSID 最长 32 字节'), '固件必须校验 SSID 长度');
});

test('固件(契约): 面板未用的冗余 API 已清理', () => {
  assert.ok(!mainCpp.includes('onAdmin("/api/handshake/status"'), '不得注册未用的握手状态路由');
  assert.ok(!mainCpp.includes('onAdmin("/api/karma/crack"'), '不得注册跑包别名路由');
  assert.ok(mainCpp.includes('onAdmin("/api/handshake/crack"'), '统一跑包路由必须保留');
});

test('文档(契约): 遥测事件表已登记 eviltwin', () => {
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf-8');
  assert.ok(readme.includes('| `eviltwin` | Evil Twin'), '遥测事件表必须列出 eviltwin 事件');
});

test('工程闭环(契约): 后台 API 与固件路由严格一一对应', () => {
  const html = readFileSync(join(ROOT, 'firmware', 'data', 'admin.html'), 'utf-8');
  const pats = [
    /api\(\s*'(\/api\/[^'\s]+)'/g,
    /fetch\(\s*'(\/api\/[^'\s]+)'/g,
    /act\(\s*'(\/api\/[^'\s]+)'/g,
  ];
  const calls = new Set(pats.flatMap((p) => [...html.matchAll(p)].map((m) => m[1].split('?')[0])));
  const routes = new Set([...mainCpp.matchAll(/onAdmin\("(\/api\/[^"]+)"/g)].map((m) => m[1]));
  assert.ok(calls.size > 20, '至少应覆盖 20 个面板 API');
  assert.deepEqual([...calls].filter((p) => !routes.has(p)), [], '不得存在面板调用但未注册的悬空 API');
  assert.deepEqual([...routes].filter((p) => !calls.has(p)), [], '不得存在固件注册但面板未用的冗余路由');
});

test('多系统引导(契约): 支持三系统槽位定义与引导切换接口', () => {
  const html = readFileSync(join(ROOT, 'firmware', 'data', 'admin.html'), 'utf-8');
  assert.ok(mainCpp.includes('SYSTEM_SLOTS'), '固件必须定义多系统引导槽位表');
  assert.ok(mainCpp.includes('"audit"') && mainCpp.includes('"espsoup"') && mainCpp.includes('"muse"'),
    '必须支持 audit / espsoup / muse 三大系统槽位');
  assert.ok(mainCpp.includes('esp_ota_set_boot_partition'), '必须调用 esp_ota_set_boot_partition 切换引导');
  assert.ok(mainCpp.includes('handleSerialCli'), '必须支持串口 CLI 切换引导');
  assert.ok(html.includes('id="bootCard"'), '后台配置页必须有多系统引导卡片');
  assert.ok(html.includes('loadBootSlots') && html.includes('doSwitchBoot'), '后台必须具备槽位加载与切换处理函数');
  const partCsv = readFileSync(join(ROOT, 'firmware', 'partitions-16mb-triple.csv'), 'utf-8');
  assert.ok(partCsv.includes('ota_0') && partCsv.includes('ota_1') && partCsv.includes('ota_2'),
    '16MB 三系统分区表必须定义 ota_0/ota_1/ota_2 三个 app 分区');
});


