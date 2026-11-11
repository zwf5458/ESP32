// 可复用的纯逻辑 (无副作用: 不打开 DB、不启动服务、不读 process.env)
// 由 server/src/index.js 与 server/test/index.test.js 共同导入, 保证测试覆盖的是真实实现。
import crypto from 'node:crypto';
import { sep } from 'node:path';

export const DEFAULT_ADMIN_TOKEN = 'local-admin-token-change-me';
export const CODE_TTL_MS = 15 * 60 * 1000;
export const VERIFY_WINDOW_MS = 60 * 1000;
export const VERIFY_LIMIT = 10;
export const CHIP_ALIASES = ['esp32', 'esp32s2', 'esp32s3', 'esp32c3', 'esp32c5', 'esp32c6'];
export const VERSION_RE = /^[a-zA-Z0-9._-]+$/;

// 判断绝对路径是否在工作区根目录内 (必须带分隔符, 防 E:\code\ESP32-other 兄弟目录误放行)
export const makeIsWithinRoot = (root) =>
  (absPath) => absPath === root || absPath.startsWith(root + sep);

// 管理口令校验: 返回 null 表示通过, 否则返回 { status, error }
// envToken 显式传入 (而非直接读 process.env), 便于测试且保持纯函数语义。
// 用定长 SHA-256 摘要做常量时间比较, 避免字符串比较按字节早退导致的时序侧信道。
export const checkAdminToken = (envToken, headerToken) => {
  const expected = envToken || DEFAULT_ADMIN_TOKEN;
  const a = crypto.createHash('sha256').update(String(expected)).digest();
  const b = crypto.createHash('sha256').update(typeof headerToken === 'string' ? headerToken : '').digest();
  const equal = crypto.timingSafeEqual(a, b);
  const provided = typeof headerToken === 'string' && headerToken.length > 0;
  return (equal && provided) ? null : { status: 401, error: '管理口令错误' };
};

// 限流用的客户端标识: 默认只采信 TCP 对端地址 (客户端不可伪造), 忽略一切转发头。
// 仅当部署在会覆盖 XFF 的可信反向代理之后并显式设置 TRUST_PROXY=1 时才采信转发头,
// 且取链尾 (由最近的可信代理追加) 而非客户端可随意伪造的链首。
export const resolveClientIp = ({ forwardedFor, realIp, remoteAddress } = {}, trustProxy = false) => {
  const fallback = String(remoteAddress || '').trim() || 'local';
  if (!trustProxy) return fallback;
  const chain = String(forwardedFor || '').split(',').map(s => s.trim()).filter(Boolean);
  if (chain.length) return chain[chain.length - 1];
  return String(realIp || '').trim() || fallback;
};

// nonce 内存表: 一码同时仅保留一个活跃 nonce
export const makeRegisterNonce = (store, ttlMs = CODE_TTL_MS) => (code, chip) => {
  for (const [nonce, entry] of store) {
    if (entry.code === code) store.delete(nonce);
  }
  const nonce = crypto.randomUUID() + '.' + crypto.randomBytes(12).toString('hex');
  store.set(nonce, { code, chip: chip || null, expiresAt: Date.now() + ttlMs });
  return nonce;
};

export const sweepExpired = (store, now = Date.now()) => {
  for (const [nonce, entry] of store) {
    if (now > entry.expiresAt) store.delete(nonce);
  }
};

// 滑动窗口限流: now 显式传入便于测试
export const makeVerifyLimiter = (hits, windowMs = VERIFY_WINDOW_MS, limit = VERIFY_LIMIT) =>
  (ip, now = Date.now()) => {
    const arr = (hits.get(ip) || []).filter(ts => now - ts < windowMs);
    arr.push(now);
    hits.set(ip, arr);
    if (arr.length > limit) {
      const retryAfterSec = Math.max(1, Math.ceil((arr[0] + windowMs - now) / 1000));
      return { blocked: true, retryAfterSec };
    }
    return { blocked: false, retryAfterSec: 0 };
  };

// 镜像下载 ETag 条件请求判定
export const etagResult = (rowMd5, ifNoneMatch) => {
  const etag = `"${rowMd5}"`;
  return ifNoneMatch === etag ? { status: 304, etag } : { status: 200, etag };
};

// 一次性码核销: 事务 + 条件更新, 返回是否真正核销 (防并发双烧)
export const redeemCode = (db, code, chipFinal, md5, now = Date.now()) => {
  const tx = db.transaction(() => {
    const res = db.prepare(
      `UPDATE codes SET status='redeemed', redeem_at=?, chip=COALESCE(?, chip) WHERE code=? AND status != 'redeemed'`
    ).run(now, chipFinal, code);
    if (res.changes === 0) return false;
    db.prepare(`INSERT INTO flash_log(chip, code, md5, result, ts) VALUES(?,?,?,?,?)`)
      .run(chipFinal, code, md5 || null, 'success', now);
    return true;
  });
  return tx();
};

// 管理统计聚合
export const summarizeStats = (db, activeNonces) => {
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
  return { ok: true, stats: summary, activeNonces };
};

// 固件热点配置校验 (与 firmware/src/main.cpp 的 handleConfig 规则一致)
export const parseChannel = (chStr) => {
  const ch = parseInt(chStr, 10);
  return (!isNaN(ch) && ch >= 1 && ch <= 13) ? ch : null;
};
export const validateSsid = (ssid) => {
  if (typeof ssid !== 'string') return false;
  const len = ssid.trim().length;
  return len >= 1 && len <= 32;
};
