// 生成内置弱口令字典（恰好 7,153 条，WPA2-PSK 最短 8 位）
// 输出:
//   firmware/src/wifi_weak_dict.h   — C 数组，供固件在设备上离线跑包
//   server/data/weak-passwords.txt  — 同序文本，供后台 /api/wpa/crack 跑包
// 规则全部确定性生成；排序 = 强度分级 → 字典序，截断只裁最弱尾部；
// 前若干条固定置顶，保证 00000000/88888888 等演示密码最先命中。
import fs from "node:fs";
import path from "node:path";

const TARGET = 7153;
const ranks = new Map(); // word → 强度分级 (越小越弱、越先跑)
const add = (s, pr) => {
  if (s.length < 8 || s.length > 16 || !/^[ -~]+$/.test(s)) return;
  if (!ranks.has(s) || ranks.get(s) > pr) ranks.set(s, pr);
};

// 0) 固定置顶 (演示/教学密码)
const PINNED = [
  "00000000", "88888888", "12345678", "1234567890", "11111111", "123456789",
  "0000000000", "8888888888", "87654321", "password", "Password1", "admin123",
  "admin888", "123123123", "abc12345", "qwerty123", "1q2w3e4r", "iloveyou",
];
PINNED.forEach((p, i) => ranks.set(p, -1000 + i));

// 1) 数字/字母序列及循环补位 (8~12 位)
for (const base of ["1234567890", "0987654321", "abcdefgh", "zyxwvuts"])
  for (let len = 8; len <= 12; len++)
    for (let off = 0; off < base.length; off++) {
      let s = "";
      for (let i = 0; i < len; i++) s += base[(off + i) % base.length];
      add(s, 1);
    }
// 2) 单一数字重复 8~13 位
for (let d = 0; d <= 9; d++) for (let len = 8; len <= 13; len++) add(String(d).repeat(len), 1);
// 3) 单位模式重复 (两位 8~12 位; 三位 9 位)
for (let a = 0; a <= 9; a++) for (let b = 0; b <= 9; b++)
  for (let r = 4; r <= 6; r++) add(`${a}${b}`.repeat(r), 2);
for (let n = 0; n <= 999; n++) add(String(n).padStart(3, "0").repeat(3), 2);
// 4) 常见单词 + 弱后缀
const WORDS = ["password", "passwort", "iloveyou", "sunshine", "princess", "qwerty",
  "asdfgh", "qwertyuiop", "abcdefg", "abcde", "abcd1234", "admin", "administrator",
  "guest", "server", "wifi", "wireless", "router", "home", "house", "love", "baby",
  "dragon", "master", "monkey", "shadow", "soccer", "football", "basketball", "hello",
  "friend", "student", "teacher", "computer", "internet", "google", "apple", "samsung",
  "huawei", "xiaomi", "tp-link", "mercury", "tenda", "secure", "secret", "test"];
const SUF = ["", "1", "12", "123", "1234", "12345", "!", "666", "888", "999", "00", "000",
  "2023", "2024", "2025", "2026", "520", "1314", "521", "168", "001", "01"];
for (const w of WORDS) {
  for (const s of SUF) add(w + s, 3);
  add(w[0].toUpperCase() + w.slice(1), 3);
  add(w.toUpperCase(), 3);
}
// 5) 拼音习惯弱口令 + 弱后缀
for (const w of ["woaini", "woshishui", "mima", "mimachao", "bucunzai", "miandeng", "meiyong", "yongbucuo", "suibian", "denglu", "shangwang", "jiazhang", "guanjia"])
  for (const s of SUF) add(w + s, 3);
// 6) 键盘行走串变体
for (const kb of ["qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsx", "1qaz2wsx", "qweasdzxc", "123qwe", "qwe123", "a1b2c3d4", "woyaoxianjiu"]) {
  add(kb, 3); add(kb + "1", 3); add(kb + "123", 3);
  add(kb[0].toUpperCase() + kb.slice(1), 3);
}
// 7) 生日式 8 位 (弱口令最高频的大类, 排最后被裁)
for (let y = 1970; y <= 2015; y++) for (const m of ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"])
  for (const d of ["01", "05", "10", "15", "20", "25", "28"]) add(`${y}${m}${d}`, 4);
// 8) 年份重复/年份+弱尾
for (let y = 1900; y <= 2099; y++) { add(`${y}${y}`, 4); add(`${y}0000`, 4); add(`${y}1234`, 4); }
// 9) QQ 式短号补零/加弱尾
for (let n = 100; n <= 140; n++) for (const s of ["", "00", "123", "888", "520"])
  add(s ? `${n}${s}` : `${n}00000`.slice(0, 8), 4);

if (ranks.size < TARGET) throw new Error(`词量不足: ${ranks.size} < ${TARGET}`);
const words = [...ranks.entries()]
  .sort((a, b) => a[1] - b[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
  .slice(0, TARGET)
  .map(([w]) => w);
if (words.length !== TARGET) throw new Error(`词数 ${words.length} != ${TARGET}`);

// ---- 输出 ----
const ROOT = path.resolve(import.meta.dirname, "..");
fs.mkdirSync(path.join(ROOT, "server", "data"), { recursive: true });
const txt = words.join("\n") + "\n";
fs.writeFileSync(path.join(ROOT, "server", "data", "weak-passwords.txt"), txt);

const arr = words.map((w) => '  "' + w.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"').join(",\n");
const h = `// 自动生成 — 请勿手改。源: tools/build-wordlist.mjs (内置弱口令字典 ${TARGET} 条, 与 server/data/weak-passwords.txt 同序)
#ifndef WIFI_WEAK_DICT_H
#define WIFI_WEAK_DICT_H
static const size_t WIFI_WEAK_DICT_COUNT = ${TARGET};
static const char *const WIFI_WEAK_DICT[${TARGET}] = {
${arr}
};
#endif
`;
fs.writeFileSync(path.join(ROOT, "firmware", "src", "wifi_weak_dict.h"), h);
console.log(`✓ ${TARGET} 条 → server/data/weak-passwords.txt + firmware/src/wifi_weak_dict.h`);
