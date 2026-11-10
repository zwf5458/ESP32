/**
 * One-off fetcher for the aircrack-ng crypto unit-test vectors that
 * server/test/index.test.js pins the WPA engine to. Run with:
 *   node tools/fetch-wpa-vectors.mjs [output.json]
 *
 * Both vectors are taken verbatim from upstream, so the reference values are the
 * ones aircrack-ng itself is tested against:
 *   test/cryptounittest/test-calc-mic.c  WPA,  SSID "Harkonen", key versions 1 + 2
 *   test/unit/test-wpapsk-cmac.c         WPA2, SSID "Neheb",     key version 3
 */
import fs from 'node:fs';
import path from 'node:path';

const BASE = 'https://cdn.jsdelivr.net/gh/aircrack-ng/aircrack-ng@master/';
const out =
  process.argv[2] ??
  path.join(import.meta.dirname, '..', 'server', 'test', 'fixtures', 'wpa-vectors.json');

const get = async (p) => {
  const res = await fetch(BASE + p);
  if (!res.ok) throw new Error(`${p}: HTTP ${res.status}`);
  return res.text();
};

const hexOnly = (text) =>
  [...text.matchAll(/\\x([0-9a-fA-F]{2})/g)].map((m) => m[1]).join('');

/** bytes of a C `unsigned char|uint8_t name[n] = "\x.." …` declaration */
function cBytes(src, name, len) {
  const m = src.match(
    new RegExp(`(?:unsigned char|uint8_t)\\s+${name}\\s*\\[\\s*\\d+\\s*\\][^;]*?=\\s*([\\s\\S]*?);`),
  );
  if (!m) throw new Error(`vector ${name} not found`);
  const hex = hexOnly(m[1]);
  if (len && hex.length !== len * 2) throw new Error(`${name}: ${hex.length / 2} bytes, expected ${len}`);
  return hex;
}

/** plain C string literal assigned to a name, e.g. `unsigned char essid[33] = "Harkonen";` */
function cString(src, name) {
  const m = src.match(
    new RegExp(`(?:unsigned char|uint8_t)\\s+${name}\\s*\\[[^\\]]*\\]\\s*=\\s*"((?:\\\\.|[^"\\\\])*?)"`),
  );
  if (!m) throw new Error(`string ${name} not found`);
  return m[1].replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/** hex of every byte literal in the assert_memory_equal(...) call that starts at `needle` */
function assertBytes(src, needle) {
  const at = src.indexOf(needle);
  if (at < 0) throw new Error(`assertion ${needle} not found`);
  const m = src.slice(at).match(/^([\s\S]*?),\s*\d+\);/);
  if (!m) throw new Error(`assertion ${needle} not terminated`);
  return hexOnly(m[1]);
}

const micSrc = await get('test/cryptounittest/test-calc-mic.c');
const cmacSrc = await get('test/unit/test-wpapsk-cmac.c');

// Both tests keep their EAPOL buffer zero-padded to 256 bytes; only eapol_size
// bytes belong to the frame (and only those are MACed).
const harkonenSize = Number(micSrc.match(/wpa\.eapol_size = (\d+)/)[1]);
const nehebSize = Number(cmacSrc.match(/eapol_size = (\d+)/)[1]);

const vectors = {
  source:
    'aircrack-ng master: test/cryptounittest/test-calc-mic.c (test-calc-mic), ' +
    'test/unit/test-wpapsk-cmac.c (test-wpapsk-cmac)',
  note:
    'The EAPOL-Key frames carry no 802.11/LLC header: byte 0 is the EAPOL packet type. The MIC field of the frame is zeroed in both vectors, which is exactly what the standard MACs over.',
  harkonen: {
    description:
      'WPA 4-way handshake M2. calc_mic() derives the PTK from the PMK and MACs the frame with HMAC-MD5 (key version 1) and HMAC-SHA1 (key version 2); the first 16 bytes of each digest are the expected MIC.',
    essid: cString(micSrc, 'essid'),
    pmk: cBytes(micSrc, 'opmk', 32),
    bssid: cBytes(micSrc, 'bssid', 6),
    stmac: cBytes(micSrc, 'stmac', 6),
    anonce: cBytes(micSrc, 'anonce', 32),
    snonce: cBytes(micSrc, 'snonce', 32),
    eapol: cBytes(micSrc, 'eapol', 256).slice(0, harkonenSize * 2),
    eapolSize: harkonenSize,
    expectedPmk: cBytes(micSrc, 'opmk', 32),
    expectedPtk: cBytes(micSrc, 'eptk', 80),
    expectedMicV1: cBytes(micSrc, 'emic1', 20).slice(0, 32),
    expectedMicV2: cBytes(micSrc, 'emic2', 20).slice(0, 32),
  },
  neheb: {
    description:
      'WPA2 with 802.11w (key version 3): PBKDF2-HMAC-SHA1 derives the PMK, the 802.11 KDF (HMAC-SHA256) derives a 32-byte KCK, and AES-CMAC over the EAPOL-Key frame with the MIC field zeroed gives the MIC.',
    essid: cString(cmacSrc, 'essid'),
    passphrase: cmacSrc.match(/strcpy\(\(char \*\) \(key\[0\]\.v\), "([^"]+)"\)/)[1],
    bssid: cBytes(cmacSrc, 'bssid', 6),
    stmac: cBytes(cmacSrc, 'stmac', 6),
    anonce: cBytes(cmacSrc, 'anonce', 32),
    snonce: cBytes(cmacSrc, 'snonce', 32),
    eapol: cBytes(cmacSrc, 'eapol', 256).slice(0, nehebSize * 2),
    eapolSize: nehebSize,
    expectedPmk: assertBytes(cmacSrc, 'assert_memory_equal(pmk,'),
    expectedPtk: assertBytes(cmacSrc, 'dso_ac_crypto_engine_get_ptk(&engine, 1, i)'),
    expectedMic: cBytes(cmacSrc, 'expected_mic').slice(0, 32),
  },
};

fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, `${JSON.stringify(vectors, null, 2)}\n`);
for (const [name, v] of Object.entries(vectors)) {
  if (name === 'source' || name === 'note') continue;
  console.log(`${name}: essid=${v.essid} eapol=${v.eapolSize}B pmk=${v.expectedPmk.slice(0, 16)}…`);
}
console.log(`written: ${out}`);
