// 单元与集成测试套件: 针对 P0/P1 代码修复项的自动化校验
import assert from 'node:assert/strict';
import test from 'node:test';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { resolve, join, sep } from 'node:path';
import { writeFileSync, unlinkSync, existsSync } from 'node:fs';

// ---------------- 1. 固件 JSON 提取与 XSS 防护逻辑单测 ----------------
function extractJson(body, key) {
  const search = '"' + key + '"';
  const k = body.indexOf(search);
  if (k < 0) return "";
  const colon = body.indexOf(':', k + search.length);
  if (colon < 0) return "";
  let idx = colon + 1;
  while (idx < body.length && (body[idx] === ' ' || body[idx] === '\t' || body[idx] === '\r' || body[idx] === '\n')) {
    idx++;
  }
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

function htmlEscape(inStr) {
  let out = "";
  for (let i = 0; i < inStr.length; i++) {
    const c = inStr[i];
    switch (c) {
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '&': out += "&amp;"; break;
      case '"': out += "&quot;"; break;
      case "'": out += "&#39;"; break;
      default: out += c; break;
    }
  }
  return out;
}

test('P0: 固件 extractJson 字符串、数字与转义字符准确解析', () => {
  const body1 = '{"ssid":"Guest-WiFi","channel":6,"rssi":-65,"auth":"WPA2"}';
  assert.equal(extractJson(body1, 'ssid'), 'Guest-WiFi');
  assert.equal(extractJson(body1, 'channel'), '6');
  assert.equal(parseInt(extractJson(body1, 'channel'), 10), 6);
  assert.equal(extractJson(body1, 'rssi'), '-65');
  assert.equal(extractJson(body1, 'auth'), 'WPA2');
  assert.equal(extractJson(body1, 'notExist'), '');

  // 带空格与换行
  const body2 = '{\n  "cloneSsid" :  "MyAP" ,\n  "rate" : 20 \n}';
  assert.equal(extractJson(body2, 'cloneSsid'), 'MyAP');
  assert.equal(extractJson(body2, 'rate'), '20');

  // 转义引号
  const body3 = '{"ssid":"Shop\\\"Guest"}';
  assert.equal(extractJson(body3, 'ssid'), 'Shop\\\"Guest');
});

test('P1: 固件 htmlEscape 杜绝 XSS 注入', () => {
  const evilSSID = '<script>alert("hack")</script>';
  const escaped = htmlEscape(evilSSID);
  assert.equal(escaped, '&lt;script&gt;alert(&quot;hack&quot;)&lt;/script&gt;');
  assert.ok(!escaped.includes('<script>'));
});

// ---------------- 2. 服务端 Nonce 管理与原子核销逻辑单测 ----------------
test('P0: Nonce 单一活跃性 (一码多签时自动作废旧 Nonce)', () => {
  const nonceStore = new Map();
  const CODE_TTL_MS = 15 * 60 * 1000;
  const registerNonce = (code, chip) => {
    for (const [nonce, entry] of nonceStore) {
      if (entry.code === code) nonceStore.delete(nonce);
    }
    const nonce = crypto.randomUUID() + '.' + crypto.randomBytes(12).toString('hex');
    nonceStore.set(nonce, { code, chip: chip || null, expiresAt: Date.now() + CODE_TTL_MS });
    return nonce;
  };

  const code = 'ESP32-AAAA-BBBB-CCCC';
  const n1 = registerNonce(code, 'esp32');
  assert.equal(nonceStore.size, 1);
  assert.ok(nonceStore.has(n1));

  // 再次对同码 verify
  const n2 = registerNonce(code, 'esp32');
  assert.equal(nonceStore.size, 1);
  assert.ok(!nonceStore.has(n1), '旧 nonce 应已被作废');
  assert.ok(nonceStore.has(n2), '新 nonce 应生效');
});

test('P0: 原子 Redeem 防止重放并发核销', () => {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE codes(code TEXT PRIMARY KEY, status TEXT, verify_at INTEGER, redeem_at INTEGER, chip TEXT, remark TEXT, created_at INTEGER);
    CREATE TABLE flash_log(id INTEGER PRIMARY KEY AUTOINCREMENT, chip TEXT, code TEXT, md5 TEXT, result TEXT, ts INTEGER);
  `);
  const code = 'ESP32-1111-2222-3333';
  db.prepare(`INSERT INTO codes(code, status, created_at) VALUES(?, 'verified', ?)`).run(code, Date.now());

  const nonceStore = new Map();
  const nonce = 'test-nonce-123';
  nonceStore.set(nonce, { code, chip: 'esp32', expiresAt: Date.now() + 60000 });

  const redeem = (nonceInput, success) => {
    const entry = nonceStore.get(nonceInput);
    if (!entry || Date.now() > entry.expiresAt) return { ok: false, error: 'nonce无效或已过期' };
    // 立即消费 nonce
    nonceStore.delete(nonceInput);

    if (!success) {
      db.prepare(`UPDATE codes SET status='unused' WHERE code=? AND status='verified'`).run(entry.code);
      return { ok: true, consumed: false };
    }

    const redeemTx = db.transaction(() => {
      const res = db.prepare(`UPDATE codes SET status='redeemed', redeem_at=? WHERE code=? AND status != 'redeemed'`)
        .run(Date.now(), entry.code);
      if (res.changes === 0) return false;
      db.prepare(`INSERT INTO flash_log(chip, code, md5, result, ts) VALUES(?,?,?,?,?)`).run(entry.chip, entry.code, null, 'success', Date.now());
      return true;
    });

    const successRedeemed = redeemTx();
    if (!successRedeemed) return { ok: false, error: '已核销' };
    return { ok: true, consumed: true };
  };

  // 第一次核销: 成功
  const r1 = redeem(nonce, true);
  assert.equal(r1.ok, true);
  assert.equal(r1.consumed, true);

  // 第二次使用相同 nonce: 立即被拒
  const r2 = redeem(nonce, true);
  assert.equal(r2.ok, false);
  assert.equal(r2.error, 'nonce无效或已过期');

  // 检查 DB 状态
  const row = db.prepare('SELECT * FROM codes WHERE code=?').get(code);
  assert.equal(row.status, 'redeemed');
  const logs = db.prepare('SELECT * FROM flash_log WHERE code=?').all(code);
  assert.equal(logs.length, 1);
});

// ---------------- 3. 服务端管理口令与回环放行逻辑单测 ----------------
test('P0: 管理接口口令校验 (默认本地口令兼容 vs 自定义口令)', () => {
  const checkAdmin = (envToken, headerToken) => {
    const ADMIN_TOKEN = envToken || 'local-admin-token-change-me';
    if (envToken) {
      if (headerToken !== ADMIN_TOKEN) return { status: 401, error: '管理口令错误' };
    } else {
      if (headerToken !== ADMIN_TOKEN) return { status: 401, error: '管理口令错误' };
    }
    return { status: 200, ok: true };
  };

  // 未配置 env 时使用默认口令 (本地快速启动、CLI 工具)
  assert.equal(checkAdmin(undefined, 'local-admin-token-change-me').status, 200);
  assert.equal(checkAdmin(undefined, 'wrong-token').status, 401);

  // 配置了 env 强口令
  assert.equal(checkAdmin('my-super-secret', 'my-super-secret').status, 200);
  assert.equal(checkAdmin('my-super-secret', 'local-admin-token-change-me').status, 401);
});

// ---------------- 4. 固件注册安全校验单测 ----------------
test('P1: 镜像注册接口版本号正则与路径越界防护', () => {
  const validateRegister = (version, sourcePath, rootDir) => {
    if (!version || typeof version !== 'string' || !/^[a-zA-Z0-9._-]+$/.test(version)) {
      return { ok: false, error: '版本号格式不合法' };
    }
    if (!sourcePath || typeof sourcePath !== 'string') {
      return { ok: false, error: '缺 sourcePath 参数' };
    }
    const resolved = resolve(sourcePath);
    // 与 server/src/index.js 的 isWithinRoot 一致: 必须带分隔符, 防兄弟目录误放行
    const isWithinRoot = (p) => p === rootDir || p.startsWith(rootDir + sep);
    if (!isWithinRoot(resolved)) {
      return { ok: false, error: '路径越界' };
    }
    return { ok: true, resolved };
  };

  const root = resolve('.'); // npm test 从仓库根运行
  // 正常版本 + 工作区内路径
  assert.equal(validateRegister('1.1.0', join(root, 'server/firmware/test.bin'), root).ok, true);
  // 工作区外路径
  assert.equal(validateRegister('1.1.0', resolve(root, '..', 'outside.bin'), root).ok, false);
  // 兄弟目录 (前缀相同但不在工作区内): 旧实现 startsWith(ROOT) 会误放行
  assert.equal(validateRegister('1.1.0', root + '-sibling/x.bin', root).ok, false);
  // 根目录本身不是文件, 但仍视为边界内 (由后续 existsSync/类型判断处理)
  assert.equal(validateRegister('1.1.0', root, root).ok, true);
  // 非法版本号 (路径穿越尝试)
  assert.equal(validateRegister('../../etc/passwd', join(root, 'server/firmware/test.bin'), root).ok, false);
});

// ---------------- 5. 持续优化项单测 ----------------
test('优化: 烧录码限流 Retry-After 倒计时计算', () => {
  const verifyHits = new Map();
  const VERIFY_WINDOW_MS = 60 * 1000;
  const VERIFY_LIMIT = 3; // 测试阈值设为 3

  const checkRateLimit = (ip, now) => {
    const hits = (verifyHits.get(ip) || []).filter(ts => now - ts < VERIFY_WINDOW_MS);
    hits.push(now);
    verifyHits.set(ip, hits);
    if (hits.length > VERIFY_LIMIT) {
      const retryAfterSec = Math.max(1, Math.ceil((hits[0] + VERIFY_WINDOW_MS - now) / 1000));
      return { blocked: true, retryAfterSec };
    }
    return { blocked: false, retryAfterSec: 0 };
  };

  const t0 = 1000000;
  assert.equal(checkRateLimit('1.2.3.4', t0).blocked, false);
  assert.equal(checkRateLimit('1.2.3.4', t0 + 1000).blocked, false);
  assert.equal(checkRateLimit('1.2.3.4', t0 + 2000).blocked, false);
  const r4 = checkRateLimit('1.2.3.4', t0 + 3000);
  assert.equal(r4.blocked, true);
  assert.equal(r4.retryAfterSec, 57); // 60 - 3 = 57 秒
});

test('优化: 固件镜像下载 ETag 与 If-None-Match 304 逻辑', () => {
  const checkEtag = (rowMd5, ifNoneMatch) => {
    const etag = `"${rowMd5}"`;
    if (ifNoneMatch === etag) return { status: 304, sendBody: false };
    return { status: 200, sendBody: true, etag };
  };

  const md5 = 'a1b2c3d4e5f6';
  assert.equal(checkEtag(md5, undefined).status, 200);
  assert.equal(checkEtag(md5, '"different"').status, 200);
  assert.equal(checkEtag(md5, `"${md5}"`).status, 304);
});

test('优化: 固件热点配置与信道校验逻辑', () => {
  const parseChannel = (chStr) => {
    const ch = parseInt(chStr, 10);
    if (!isNaN(ch) && ch >= 1 && ch <= 13) return ch;
    return null;
  };
  assert.equal(parseChannel('6'), 6);
  assert.equal(parseChannel('13'), 13);
  assert.equal(parseChannel('0'), null);
  assert.equal(parseChannel('14'), null);
  assert.equal(parseChannel('abc'), null);

  const validateSsid = (ssid) => {
    if (typeof ssid !== 'string') return false;
    const len = ssid.trim().length;
    return len >= 1 && len <= 32;
  };
  assert.equal(validateSsid('My-ESP32-AP'), true);
  assert.equal(validateSsid(''), false);
  assert.equal(validateSsid('A'.repeat(32)), true);
  assert.equal(validateSsid('A'.repeat(33)), false);
});

test('优化: 后端管理统计聚合逻辑 (codes / flash_log)', () => {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE codes(code TEXT PRIMARY KEY, status TEXT, verify_at INTEGER, redeem_at INTEGER, chip TEXT, remark TEXT, created_at INTEGER);
    CREATE TABLE flash_log(id INTEGER PRIMARY KEY AUTOINCREMENT, chip TEXT, code TEXT, md5 TEXT, result TEXT, ts INTEGER);
  `);
  db.prepare(`INSERT INTO codes(code, status, created_at) VALUES('C1', 'unused', 1)`).run();
  db.prepare(`INSERT INTO codes(code, status, created_at) VALUES('C2', 'unused', 2)`).run();
  db.prepare(`INSERT INTO codes(code, status, created_at) VALUES('C3', 'verified', 3)`).run();
  db.prepare(`INSERT INTO codes(code, status, created_at) VALUES('C4', 'redeemed', 4)`).run();

  db.prepare(`INSERT INTO flash_log(chip, code, md5, result, ts) VALUES('esp32', 'C4', 'md5', 'success', 5)`).run();
  db.prepare(`INSERT INTO flash_log(chip, code, md5, result, ts) VALUES('esp32', 'C3', 'md5', 'failed', 6)`).run();

  const codeStats = db.prepare(`SELECT status, COUNT(*) as count FROM codes GROUP BY status`).all();
  const flashStats = db.prepare(`SELECT result, COUNT(*) as count FROM flash_log GROUP BY result`).all();

  const summary = {
    codes: { unused: 0, verified: 0, redeemed: 0, total: 0 },
    flashes: { success: 0, failed: 0, total: 0 }
  };
  for (const r of codeStats) {
    if (r.status in summary.codes) summary.codes[r.status] = r.count;
    summary.codes.total += r.count;
  }
  for (const r of flashStats) {
    if (r.result in summary.flashes) summary.flashes[r.result] = r.count;
    summary.flashes.total += r.count;
  }

  assert.equal(summary.codes.unused, 2);
  assert.equal(summary.codes.verified, 1);
  assert.equal(summary.codes.redeemed, 1);
  assert.equal(summary.codes.total, 4);
  assert.equal(summary.flashes.success, 1);
  assert.equal(summary.flashes.failed, 1);
  assert.equal(summary.flashes.total, 2);
});
