// ESP32 无线固件烧录台后端
// Hono + @hono/node-server + better-sqlite3
// 运行: node server/src/index.js   (工作目录必须为仓库根)
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { Hono } from 'hono';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIRMWARE_DIR = join(ROOT, 'server', 'firmware');
const DB_PATH = join(ROOT, 'server', 'db.sqlite');
const PORT = Number(process.env.PORT || 8787);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'local-admin-token-change-me';
const CODE_TTL_MS = 15 * 60 * 1000; // verify 后 nonce 有效期

mkdirSync(FIRMWARE_DIR, { recursive: true });

// ---------- 数据库 ----------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS codes(
  code TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'unused',   -- unused | verified | redeemed
  verify_at INTEGER,
  redeem_at INTEGER,
  chip TEXT,
  remark TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS firmwares(
  chip TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  bin_path TEXT NOT NULL,
  md5 TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS flash_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chip TEXT, code TEXT, md5 TEXT, result TEXT, ts INTEGER NOT NULL
);
`);

// ---------- 常量 ----------
const CHIP_ALIASES = ['esp32', 'esp32s2', 'esp32s3', 'esp32c3', 'esp32c5', 'esp32c6'];

// nonce 内存表: nonce -> { code, chip, expiresAt }
const nonceStore = new Map();
const registerNonce = (code, chip) => {
  const nonce = crypto.randomUUID() + '.' + crypto.randomBytes(12).toString('hex');
  nonceStore.set(nonce, { code, chip: chip || null, expiresAt: Date.now() + CODE_TTL_MS });
  return nonce;
};
const readBody = async (c) => {
  try { return (await c.req.json()) ?? {}; } catch { return {}; }
};

// ---------- App ----------
const app = new Hono();
const json = (c, obj, status = 200) => c.json(obj, status);

const requireAdmin = async (c, next) => {
  if (c.req.header('x-admin-token') !== ADMIN_TOKEN) return json(c, { error: '管理口令错误' }, 401);
  await next();
};

// ---------- 固件 manifest ----------
app.get('/api/firmware/manifest', (c) => {
  const rows = db.prepare('SELECT chip, version, md5, size, created_at FROM firmwares ORDER BY chip').all();
  const chips = {};
  for (const r of rows) {
    chips[r.chip] = { version: r.version, md5: r.md5, size: r.size, createdAt: r.created_at };
  }
  return json(c, { chips, supported: CHIP_ALIASES });
});

// 下载镜像
app.get('/api/firmware/bin/:chip', (c) => {
  const chip = c.req.param('chip');
  if (!CHIP_ALIASES.includes(chip)) return json(c, { error: '不支持的芯片' }, 400);
  const row = db.prepare('SELECT bin_path, version FROM firmwares WHERE chip = ?').get(chip);
  if (!row || !existsSync(row.bin_path)) return json(c, { error: '该芯片暂无固件镜像' }, 404);
  const buf = readFileSync(row.bin_path);
  c.header('Content-Type', 'application/octet-stream');
  c.header('Content-Disposition', `inline; filename="firmware-${chip}-${row.version}.bin"`);
  c.header('X-Firmware-Version', row.version);
  return c.body(new Uint8Array(buf));
});

// ---------- 烧录码 ----------
// 校验: 一次性码 → 发一次性 nonce (烧录成功核销, 失败不扣)
app.post('/api/codes/verify', async (c) => {
  const { code, chip = null } = await readBody(c);
  if (!code || typeof code !== 'string') return json(c, { error: '请输入烧录码' }, 400);
  const row = db.prepare('SELECT * FROM codes WHERE code = ?').get(code.trim().toUpperCase());
  if (!row) return json(c, { error: '烧录码不存在, 请检查输入' }, 404);
  if (row.status === 'redeemed') {
    return json(c, { error: '该烧录码已被核销, 每个码只能成功烧录一次' }, 400);
  }
  // unused 或 verified(烧失败没扣) 均可重新校验 → 发新 nonce, 旧的自动过期书续用
  const nonce = registerNonce(row.code, chip);
  db.prepare(`UPDATE codes SET status='verified', verify_at=?, chip=COALESCE(?, chip) WHERE code=?`)
    .run(Date.now(), chip, row.code);
  return json(c, { ok: true, nonce, expiresInMs: CODE_TTL_MS, chip: row.chip });
});

// 核销 / 失败上报: 必须携带有效 nonce
app.post('/api/codes/redeem', async (c) => {
  const { nonce, chip, md5, success } = await readBody(c);
  if (!nonce || !nonceStore.has(nonce)) {
    return json(c, { error: '校验记录不存在或已过期, 请重新校验烧录码' }, 400);
  }
  const entry = nonceStore.get(nonce);
  const chipFinal = chip || entry.chip || null;

  if (!success) {
    // 烧录失败: 释放 nonce, 码可在下次 verify 重试, 不核销
    nonceStore.delete(nonce);
    db.prepare(`UPDATE codes SET status='unused' WHERE code=? AND status='verified'`).run(entry.code);
    db.prepare(`INSERT INTO flash_log(chip, code, md5, result, ts) VALUES(?,?,?,?,?)`)
      .run(chipFinal, entry.code, md5 || null, 'failed', Date.now());
    return json(c, { ok: true, consumed: false, message: '烧录失败, 烧录码未核销, 可修正问题后重试' });
  }

  const row = db.prepare('SELECT * FROM codes WHERE code = ?').get(entry.code);
  if (!row || row.status === 'redeemed') {
    nonceStore.delete(nonce);
    return json(c, { error: '该烧录码已被核销' }, 400);
  }
  const now = Date.now();
  db.prepare(`UPDATE codes SET status='redeemed', redeem_at=?, chip=COALESCE(?, chip) WHERE code=?`)
    .run(now, chipFinal, row.code);
  db.prepare(`INSERT INTO flash_log(chip, code, md5, result, ts) VALUES(?,?,?,?,?)`)
    .run(chipFinal, row.code, md5 || null, 'success', now);
  nonceStore.delete(nonce);
  return json(c, { ok: true, consumed: true, chip: chipFinal, message: `烧录码已核销 (${chipFinal || '未知芯片'})` });
});

// ---------- 管理接口 ----------
app.post('/api/admin/codes', requireAdmin, async (c) => {
  const { count = 5, remark = null } = await readBody(c);
  const n = Math.max(1, Math.min(500, Number(count) || 5));
  const insert = db.prepare(`INSERT INTO codes(code, status, remark, created_at) VALUES(?,'unused',?,?)`);
  const gen = db.transaction((cnt) => {
    const codes = [];
    for (let i = 0; i < cnt; i++) {
      const code = 'ESP32-' + Array.from({ length: 3 }, () =>
        crypto.randomBytes(2).toString('hex').toUpperCase().padStart(4, '0')).join('-');
      insert.run(code, remark, Date.now());
      codes.push(code);
    }
    return codes;
  });
  return json(c, { ok: true, codes: gen(n) });
});

app.get('/api/admin/codes', requireAdmin, (c) => {
  const rows = db.prepare(`SELECT code, status, verify_at, redeem_at, chip, remark, created_at
                           FROM codes ORDER BY created_at DESC LIMIT 500`).all();
  return json(c, { codes: rows });
});

app.get('/api/admin/flash-log', requireAdmin, (c) => {
  const rows = db.prepare('SELECT * FROM flash_log ORDER BY ts DESC LIMIT 200').all();
  return json(c, { log: rows });
});

// 注册/替换镜像 (本地 tools 注册用): 二进制直接上传或给 sourcePath
app.post('/api/admin/firmware/:chip', requireAdmin, async (c) => {
  const chip = c.req.param('chip');
  if (!CHIP_ALIASES.includes(chip)) return json(c, { error: '不支持的芯片' }, 400);
  const { version = '1.0.0', sourcePath = null } = await readBody(c);
  if (!sourcePath || !existsSync(sourcePath)) return json(c, { error: '缺 sourcePath 或文件不存在' }, 400);
  const buf = readFileSync(sourcePath);
  // 合并镜像从 bootloader 头开始, ESP image magic 固定 0xE9
  if (buf[0] !== 0xE9) {
    return json(c, { error: `镜像魔数不符 (期望 0xE9, 实际 0x${buf[0]?.toString(16)}), 拒绝注册` }, 400);
  }
  const dest = join(FIRMWARE_DIR, `firmware-${chip}-${version}.bin`);
  writeFileSync(dest, buf);
  const md5 = crypto.createHash('md5').update(buf).digest('hex');
  db.prepare(`
    INSERT INTO firmwares(chip, version, bin_path, md5, size, created_at)
    VALUES(?,?,?,?,?,?)
    ON CONFLICT(chip) DO UPDATE SET version=excluded.version, bin_path=excluded.bin_path,
      md5=excluded.md5, size=excluded.size, created_at=excluded.created_at
  `).run(chip, version, dest, md5, buf.length, Date.now());
  return json(c, { ok: true, chip, version, md5, size: buf.length });
});

// ---------- 静态托管 ----------
// 注意: serveStatic 的 root 相对进程 cwd, 需在仓库根目录运行本服务
// no-store: 烧录台前端属迭代频繁的开发工具, 强制浏览器每次取最新 (避免旧 JS/样式)
app.use('/flasher/*', async (c, next) => { await next(); c.header('Cache-Control', 'no-store'); });
app.use('/flasher/*', serveStatic({ root: 'flasher', rewriteRequestPath: (p) => p.replace(/^\/flasher\/?/, '') || 'index.html' }));
app.get('/', (c) => c.redirect('/flasher/index.html'));

serve({ fetch: app.fetch, port: PORT }, (info) => {
  console.log(`[server] 烧录台:  http://localhost:${info.port}`);
  console.log(`[server] manifest: http://localhost:${info.port}/api/firmware/manifest`);
  console.log(`[server] 管理口令 ADMIN_TOKEN=${ADMIN_TOKEN}`);
});
