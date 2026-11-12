import crypto from 'node:crypto';

/**
 * WPA2-PSK key derivation and 4-way-handshake MIC verification — the "跑包"
 * engine, mirroring aircrack-ng / hostapd:
 *
 *   PMK   = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32)      (both are UTF-8)
 *   KDD   = min(SPA,AA) ‖ max(SPA,AA) ‖ min(SNonce,ANonce) ‖ max(…)
 *   PTK   = PRF-X(PMK, "Pairwise key expansion", KDD)
 *             key version 1/2 (WPA / WPA2) → PRF-512, SHA1 blocks of 20 bytes
 *             key version 3 (PMF / WPA3)   → 802.11 KDF, HMAC-SHA256 blocks
 *           KCK = PTK[0…16] for versions 1-2, PTK[0…32] for version 3
 *   M2-MIC (EAPOL-Key frame with the MIC field zeroed, first 16 bytes):
 *             version 1 → HMAC-MD5(KCK, eapol)
 *             version 2 → HMAC-SHA1(KCK, eapol)
 *             version 3 → AES-CMAC(KCK, eapol)
 *   PMKID = HMAC-SHA1(PMK, "PMK Name" ‖ AA ‖ SPA)[0…16]      (WPA2-PSK)
 *
 * The MIC input is the EAPOL PDU as it appears on air (from the 0x01/0x02
 * packet type byte through the last RSN-ie byte) with the 16-byte MIC field at
 * offset 81 zeroed — the frame layout is struct ieee802_1x_hdr + struct
 * wpa_eapol_key, which puts key_mic at 4 + 77. Verified against the
 * aircrack-ng crypto unit tests (see test/index.test.js).
 */

const KDF_LABEL = Buffer.from('Pairwise key expansion', 'ascii');
const PMKID_LABEL = Buffer.from('PMK Name', 'ascii');
export const EAPOL_KEY_MIC_OFFSET = 81;
export const MIC_LEN = 16;
/** Key Data Length sits right behind the MIC; Key Data two bytes further on. */
export const KEY_DATA_OFFSET = EAPOL_KEY_MIC_OFFSET + MIC_LEN + 2;
export const PBKDF2_ITERATIONS = 4096;

/* ---------------------------------------------------------------- hashing */

const hmacMd5 = (key, data) => crypto.createHmac('md5', key).update(data).digest();
const hmacSha1 = (key, data) => crypto.createHmac('sha1', key).update(data).digest();
const hmacSha256 = (key, data) => crypto.createHmac('sha256', key).update(data).digest();

/**
 * PRF-X as defined in IEEE 802.11i-2004 8.5.1.1 (hostapd prf-512, aircrack-ng
 * SHA1_PRF): every 20-byte block is an independent HMAC over
 *   label ‖ 0x00 ‖ data ‖ counter
 * with the counter counting blocks from 0x00 — the blocks are NOT chained
 * through an A_i value (that is the TLS-style PRF, not the 802.11 one).
 */
function prfSha1(key, label, data, length) {
  const labelled = Buffer.concat([label, Buffer.from([0])]);
  const out = [];
  let pos = 0;
  let counter = 0;
  while (pos < length) {
    const block = hmacSha1(key, Buffer.concat([labelled, data, Buffer.from([counter & 0xff])]));
    const take = Math.min(block.length, length - pos);
    out.push(block.subarray(0, take));
    pos += take;
    counter += 1;
  }
  return Buffer.concat(out);
}

/**
 * Key derivation function of IEEE 802.11-2016 13.6.13.2 / aircrack-ng
 * Digest_SHA256_PRF_Bits: block i = HMAC-SHA256(key, LE16(i) ‖ label ‖ data ‖
 * LE16(bits)), i starting at 1, truncated to `length` bytes.
 */
function kdfSha256(key, label, data, length) {
  const bits = Buffer.alloc(2);
  bits.writeUInt16LE(length * 8);
  const out = [];
  let pos = 0;
  let counter = 1;
  while (pos < length) {
    const counterLe = Buffer.alloc(2);
    counterLe.writeUInt16LE(counter);
    const block = hmacSha256(key, Buffer.concat([counterLe, label, data, bits]));
    const take = Math.min(block.length, length - pos);
    out.push(block.subarray(0, take));
    pos += take;
    counter += 1;
  }
  return Buffer.concat(out);
}

/** AES-CMAC (RFC 4493 / NIST SP 800-38B) with a 128-, 192- or 256-bit key. */
export function aesCmac(key, message) {
  const alg = { 16: 'aes-128-ecb', 24: 'aes-192-ecb', 32: 'aes-256-ecb' }[key.length];
  if (!alg) throw new Error(`CMAC needs a 16/24/32 byte key, got ${key.length}`);
  const ecb = (block) => {
    const c = crypto.createCipheriv(alg, key, null);
    c.setAutoPadding(false);
    return Buffer.concat([c.update(block), c.final()]);
  };
  const shl1 = (b) => {
    const out = Buffer.alloc(b.length);
    let carry = 0;
    for (let i = b.length - 1; i >= 0; i--) {
      out[i] = ((b[i] << 1) | carry) & 0xff;
      carry = b[i] & 0x80 ? 1 : 0;
    }
    if (b[0] & 0x80) out[b.length - 1] ^= 0x87; // Rb for 128-bit blocks
    return out;
  };
  const zero = Buffer.alloc(16);
  const k1 = shl1(ecb(zero));
  const k2 = shl1(k1);

  const n = Math.max(1, Math.ceil(message.length / 16));
  const lastComplete = message.length > 0 && message.length % 16 === 0;
  let last;
  if (lastComplete) {
    last = Buffer.from(message.subarray((n - 1) * 16));
    for (let i = 0; i < 16; i++) last[i] ^= k1[i];
  } else {
    const start = message.subarray(0, (n - 1) * 16);
    const tail = message.subarray((n - 1) * 16);
    last = Buffer.concat([start, tail, Buffer.from([0x80]), Buffer.alloc(16 - tail.length - 1)]).subarray((n - 1) * 16);
    for (let i = 0; i < 16; i++) last[i] ^= k2[i];
  }

  let x = Buffer.alloc(16);
  for (let i = 0; i < n - 1; i++) x = ecb(xoring(x, message.subarray(i * 16, (i + 1) * 16)));
  return ecb(xoring(x, last));
}

function xoring(a, b) {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/* --------------------------------------------------------------- WPA/PSK */

/** PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32). */
export function pbkdf2Sha1(passphrase, ssid) {
  return crypto.pbkdf2Sync(
    Buffer.from(String(passphrase), 'utf8'),
    Buffer.from(String(ssid), 'utf8'),
    PBKDF2_ITERATIONS,
    32,
    'sha1',
  );
}

const asBuf = (v) => (Buffer.isBuffer(v) ? v : Buffer.from(String(v), 'hex'));

function keyDerivationMaterial({ aa, spa, anonce, snonce }) {
  const a = asBuf(aa);
  const b = asBuf(spa);
  const an = asBuf(anonce);
  const sn = asBuf(snonce);
  if (a.length !== 6 || b.length !== 6) throw new Error('AA/SPA must be 6 bytes');
  if (an.length !== 32 || sn.length !== 32) throw new Error('nonces must be 32 bytes');
  const [macA, macB] = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
  const [nonA, nonB] = Buffer.compare(an, sn) <= 0 ? [an, sn] : [sn, an];
  return Buffer.concat([macA, macB, nonA, nonB]);
}

/**
 * KCK for the given key version: 16 bytes for WPA/WPA2 (versions 1-2, SHA1 PRF),
 * 32 bytes for PMF/WPA3 (version 3, SHA256 KDF). The KDF is always run for the
 * full 48-byte PTK because its length field is part of the hash input — the KCK
 * is simply the first 32 bytes of that output.
 */
export function deriveKck({ pmk, aa, spa, anonce, snonce, keyver = 2 }) {
  const kdd = keyDerivationMaterial({ aa, spa, anonce, snonce });
  if (keyver >= 3) return kdfSha256(pmk, KDF_LABEL, kdd, 48).subarray(0, 32);
  return prfSha1(pmk, KDF_LABEL, kdd, 16);
}

/** PTK = KCK ‖ TK ‖ … (80 bytes for versions 1-2, 48 bytes for version 3). */
export function derivePtk({ pmk, aa, spa, anonce, snonce, keyver = 2 }) {
  const kdd = keyDerivationMaterial({ aa, spa, anonce, snonce });
  if (keyver >= 3) return kdfSha256(pmk, KDF_LABEL, kdd, 48);
  return prfSha1(pmk, KDF_LABEL, kdd, 80);
}

/** EAPOL-Key body with the MIC field zeroed: the only thing that is MACed. */
export function micInput(eapol) {
  if (eapol.length < EAPOL_KEY_MIC_OFFSET + MIC_LEN) {
    throw new Error(`EAPOL-Key frame too short (${eapol.length} bytes)`);
  }
  const body = Buffer.from(eapol);
  body.fill(0, EAPOL_KEY_MIC_OFFSET, EAPOL_KEY_MIC_OFFSET + MIC_LEN);
  return body;
}

/** MIC over the EAPOL-Key frame, selected by key version (see header note). */
export function eapolKeyMic({ kck, eapol, keyver = 2 }) {
  const body = micInput(eapol);
  // Version 0 is the pre-standard TKIP form, which also uses HMAC-MD5.
  if (keyver <= 1) return hmacMd5(kck.subarray(0, MIC_LEN), body).subarray(0, MIC_LEN);
  if (keyver >= 3) return aesCmac(kck.subarray(0, 16), body);
  return hmacSha1(kck.subarray(0, MIC_LEN), body).subarray(0, MIC_LEN);
}

/**
 * verifyM2Mic: recompute the MIC of a captured M2 (EAPOL-Key frame, no
 * 802.11/LLC header) and compare it with the MIC carried by the frame.
 */
export function verifyM2Mic({ kck, eapol, keyver = 2 }) {
  if (eapol.length < EAPOL_KEY_MIC_OFFSET + MIC_LEN) return false;
  const expected = eapol.subarray(EAPOL_KEY_MIC_OFFSET, EAPOL_KEY_MIC_OFFSET + MIC_LEN);
  return crypto.timingSafeEqual(eapolKeyMic({ kck, eapol, keyver }), expected);
}

/** PMKID = HMAC-SHA1(PMK, "PMK Name" ‖ AA ‖ SPA)[0…16] (WPA2-PSK). */
export function derivePmkid({ pmk, aa, spa }) {
  const a = asBuf(aa);
  const b = asBuf(spa);
  if (a.length !== 6 || b.length !== 6) throw new Error('AA/SPA must be 6 bytes');
  return hmacSha1(pmk, Buffer.concat([PMKID_LABEL, a, b])).subarray(0, MIC_LEN);
}

/* -------------------------------------------- demo helper: build a real M2 */

/**
 * buildEapolM2: assemble a byte-exact EAPOL-Key frame (M2) with a correct RSN
 * vendor ie (OUI 00-0F-AC, WPA2-AES) — the same bytes an ESP32-C5 soft-AP would
 * put on air, so MIC verification exercises the real frame layout (including the
 * MIC field at offset 81) and not a made-up structure. Passing `kck` seals the
 * frame the way an AP does, which is how the self-test cracks a frame it built.
 */
export function buildEapolM2({
  snonce,
  replay = 3,
  keyver = 2,
  kck = null,
  rsn = Buffer.from('3014010000' + '0fac04' + '010000' + '0fac04' + '010000' + '0fac02' + '0100', 'hex'),
}) {
  const sn = asBuf(snonce);
  if (sn.length !== 32) throw new Error('SNonce must be 32 bytes');
  const keyData = asBuf(rsn);
  const body = Buffer.alloc(KEY_DATA_OFFSET + keyData.length);
  body.writeUInt8(0x02, 0); // EAPOL packet type: key
  body.writeUInt8(0x03, 1); // version 3 (802.1X-2004)
  body.writeUInt16BE(body.length - 4, 2); // body length
  body[4] = 0x02; // descriptor type: EAPOL-Key
  // Real M2 Key Info, as an AP sends it: MIC (0x0100) + Pairwise (0x0008) + the
  // key version in the low three bits (hostapd WPA_KEY_INFO_TYPE_MASK).
  const keyInfo = 0x0100 | 0x0008 | (keyver & 0x0007);
  body.writeUInt16BE(keyInfo, 5);
  body.writeUInt16BE(16, 7); // key length (TKIP / CCMP: 16)
  body.writeBigUInt64BE(BigInt(replay), 9); // replay counter (8 bytes)
  sn.copy(body, 17); // key nonce: SNonce in M2
  // key IV / RSC / ID fields (49…80) stay zero, the MIC (81…96) is filled in
  body.writeUInt16BE(keyData.length, KEY_DATA_OFFSET - 2);
  keyData.copy(body, KEY_DATA_OFFSET);
  // Sealing with the KCK turns the frame into an authentic M2 — this is what an
  // AP does, and what lets a self-test crack a frame it built itself.
  if (kck) eapolKeyMic({ kck, eapol: body, keyver }).copy(body, EAPOL_KEY_MIC_OFFSET);
  return body;
}

/* ------------------------------------------------------- offline 跑包 (crack) */

/**
 * crackHandshake: the "跑包" the reference firmware cannot do — try every
 * candidate password of a weak-password dictionary against a captured M2:
 * PMK = PBKDF2(pass, ESSID) → KCK → recompute the MIC and compare it with the
 * one the frame carries. The first candidate whose MIC matches is the
 * passphrase; the result is the dictionary index plus how long it took.
 *
 * `eapol` is the EAPOL-Key frame as captured (no 802.11/LLC header); the ANonce
 * has to come from its M1, which the capture procedure recorded. `keyver`
 * overrides the version bits of the frame when the AP did not set them.
 */
export function crackHandshake({
  essid,
  candidates,
  eapol,
  anonce,
  aa,
  spa,
  keyver,
  maxCandidates = 0,
}) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    throw new Error('no candidate passwords given');
  }
  if (!Buffer.isBuffer(eapol)) throw new Error('a captured EAPOL-Key frame is required');
  if (!anonce || !aa || !spa) throw new Error('anonce, aa and spa are required');
  const frame = eapol;
  const parsed = parseM2(frame);
  const keyInfo = keyver ?? parsed.keyver;
  const kddParts = { aa, spa, anonce, snonce: parsed.snonce };
  const carried = frame.subarray(EAPOL_KEY_MIC_OFFSET, EAPOL_KEY_MIC_OFFSET + MIC_LEN);
  const limit = maxCandidates > 0 ? Math.min(candidates.length, maxCandidates) : candidates.length;
  for (let i = 0; i < limit; i++) {
    const kck = deriveKck({
      pmk: pbkdf2Sha1(candidates[i], essid),
      ...kddParts,
      keyver: keyInfo,
    });
    if (crypto.timingSafeEqual(eapolKeyMic({ kck, eapol: frame, keyver: keyInfo }), carried)) {
      return { index: i, candidate: String(candidates[i]), attempts: i + 1, keyver: keyInfo };
    }
  }
  return { index: -1, candidate: null, attempts: limit, keyver: keyInfo };
}

/**
 * crackHandshakeAsync: 异步分批跑包，每执行 batchSize 次 PBKDF2 计算即通过 setImmediate
 * 让出事件循环，避免长时间计算阻塞 Node.js 处理其他网络请求（心跳、烧录、监控等）。
 */
export async function crackHandshakeAsync({
  essid,
  candidates,
  eapol,
  anonce,
  aa,
  spa,
  keyver,
  maxCandidates = 0,
  batchSize = 25,
}) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    throw new Error('no candidate passwords given');
  }
  if (!Buffer.isBuffer(eapol)) throw new Error('a captured EAPOL-Key frame is required');
  if (!anonce || !aa || !spa) throw new Error('anonce, aa and spa are required');
  const frame = eapol;
  const parsed = parseM2(frame);
  const keyInfo = keyver ?? parsed.keyver;
  const kddParts = { aa, spa, anonce, snonce: parsed.snonce };
  const carried = frame.subarray(EAPOL_KEY_MIC_OFFSET, EAPOL_KEY_MIC_OFFSET + MIC_LEN);
  const limit = maxCandidates > 0 ? Math.min(candidates.length, maxCandidates) : candidates.length;
  for (let i = 0; i < limit; i++) {
    const kck = deriveKck({
      pmk: pbkdf2Sha1(candidates[i], essid),
      ...kddParts,
      keyver: keyInfo,
    });
    if (crypto.timingSafeEqual(eapolKeyMic({ kck, eapol: frame, keyver: keyInfo }), carried)) {
      return { index: i, candidate: String(candidates[i]), attempts: i + 1, keyver: keyInfo };
    }
    if ((i + 1) % batchSize === 0) {
      await new Promise((resolve) => setImmediate(resolve));
    }
  }
  return { index: -1, candidate: null, attempts: limit, keyver: keyInfo };
}

/** parseM2: pull the fields the 4-way handshake needs out of an EAPOL-Key frame. */
export function parseM2(eapol) {
  if (eapol.length < EAPOL_KEY_MIC_OFFSET + MIC_LEN) {
    throw new Error(`EAPOL-Key frame too short (${eapol.length} bytes)`);
  }
  const keyInfo = eapol.readUInt16BE(5);
  return {
    // hostapd reads the key version as the low two bits of the Key Info field
    // (WPA_KEY_INFO_TYPE_MASK): 0/1 = HMAC-MD5, 2 = HMAC-SHA1, 3 = AES-CMAC.
    keyver: keyInfo & 0x0003,
    mic: Buffer.from(eapol.subarray(EAPOL_KEY_MIC_OFFSET, EAPOL_KEY_MIC_OFFSET + MIC_LEN)),
    snonce: Buffer.from(eapol.subarray(17, 49)),
    // Replay counter is 8 bytes; Number keeps it exact for every counter an AP
    // can realistically use, and JSON-safe for the API response.
    replay: Number(eapol.readBigUInt64BE(9)),
    keyDataLength: eapol.readUInt16BE(KEY_DATA_OFFSET - 2),
  };
}
