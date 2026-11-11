// 烧录台前端主逻辑: Web Serial + esptool-js 0.7.1 (本地固定版本, 见 vendor/README.md)
// 0.7.x 才有 ESP32-C5 目标与 detectFlashSize(); 0.5.x 既不能识别 C5, 也没有读 Flash 能力
import { ESPLoader, Transport } from "./vendor/esptool-js-0.7.1.js";

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const two = (n) => String(n).padStart(2, "0");
// Uint8Array → latin1 串: CryptoJS 只能吃字符串入参, 分块避免超长参数爆栈
function u8ToLatin1(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  }
  return s;
}
const nowTs = () => {
  const d = new Date();
  return `[${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}]`;
};

// ---------- 状态 ----------
const state = {
  manifest: { chips: {}, supported: [] },
  chipManual: false,
  port: null,          // 已授权 SerialPort
  transport: null,
  esploader: null,
  chip: null,          // manifest 键: esp32 / esp32s3 ...
  bin: null,           // Uint8Array 镜像 (writeFlash 入参)
  binStr: null,        // 同一份镜像的 latin1 串 (仅供 CryptoJS 计算 MD5, 下载时生成一次复用)
  binMd5: null,
  flashVersion: null,
  code: null,          // 已校验的烧录码
  nonce: null,
  consoleConn: false,  // 是否处于控制台读取模式
  backingUp: false,    // 是否正在备份 Flash
  flashing: false,     // 是否正在烧录
};

const BAUD_FLASH = 921600;
const BAUD_CONSOLE = 115200;

// ---------- 通用 UI ----------
function setStatus(connected, text) {
  const el = $('serialStatus');
  el.classList.toggle('on', connected);
  $('serialStatusText').textContent = text;
}
function msg(text, cls = '') {
  const el = $('codeHint');
  el.textContent = text;
  el.className = 'hint ' + cls;
}
function progress(pct, label) {
  $('progress').style.width = pct + '%';
  $('progressLabel').textContent = label;
}
function terminalAppend(text) {
  const el = $('console');
  const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 4;
  el.textContent += text;
  if (atBottom) el.scrollTop = el.scrollHeight;
}

// esptool-js 终端适配器: 把 loader 输出导向我们的控制台
const loaderTerminal = {
  clean() { $('console').textContent = ''; },
  writeLine(d) { terminalAppend(nowTs() + ' ' + d + '\n'); },
  write(d) { terminalAppend(d); },
};

// ---------- 开机欢迎信息 (对齐参考站控制台样式) ----------
function bootBanner() {
  $('console').textContent =
    `${nowTs()} ESP32无线网络开发固件烧录台就绪\n` +
    `${nowTs()} 流程: ①选择串口（自动连接） → ②输入并校验烧录码 → ③选择开发板 → ④勾选免责声明 → ⑤烧录\n` +
    `${nowTs()} 波特率固定: 烧录 ${BAUD_FLASH / 1000} / 控制台 ${BAUD_CONSOLE / 1000}\n` +
    `${nowTs()} 备份: ③ 卡片「💾 备份固件」可整片读回 Flash (只读, 不消耗烧录码)\n` +
    `${nowTs()} 注意: 每个烧录码只能成功烧录一次；烧录失败不消耗烧录码。\n`;
}

// ---------- 固件清单 ----------
async function loadManifest() {
  try {
    const r = await fetch('/api/firmware/manifest');
    state.manifest = await r.json();
    const chips = Object.entries(state.manifest.chips);
    if (!chips.length) {
      terminalAppend(`${nowTs()} [manifest] 服务端暂无固件镜像, 请先运行 tools/build-firmware.sh 编译注册\n`);
      return;
    }
    // 版本取所有芯片一致值 (同一次构建)
    const versions = [...new Set(chips.map(([, v]) => v.version))];
    const ver = versions[0];
    state.fwVersion = ver;
    $('fwLabel').textContent = ver;
    $('fwLabel-mini').textContent = 'v' + ver;
    const totalKB = chips.reduce((a, [, v]) => a + v.size, 0) / 1024;
    const names = chips.map(([k]) => k.replace(/^esp32/, '').toUpperCase() || 'ESP32').join('/');
    $('fwNote').textContent = `${ver} 版本覆盖 ${chips.length} 个芯片系列 (${names})，合计镜像 ${(totalKB / 1024).toFixed(1)} MB`;
    terminalAppend(`${nowTs()} [manifest] 可用镜像: ${chips.map(([k, v]) => `${k} @v${v.version}`).join(' ')}\n`);
    terminalAppend(`${nowTs()} 请先连接串口识别开发板型号。\n`);
    populateChipSelect();
  } catch (e) {
    terminalAppend(`${nowTs()} [manifest] 加载失败: ${e.message}\n`);
  }
}

function populateChipSelect() {
  const sel = $('chipLabel');
  sel.innerHTML = '<option value="">— 自动识别（推荐）—</option>';
  for (const key of state.manifest.supported) {
    const fw = state.manifest.chips[key];
    if (!fw) continue;
    const opt = document.createElement('option');
    opt.value = key;
    opt.textContent = chipDisplayName(key);
    sel.appendChild(opt);
  }
  for (const key of state.manifest.supported) {
    if (state.manifest.chips[key]) continue;
    const opt = document.createElement('option');
    opt.value = `exp:${key}`;
    opt.disabled = true;
    opt.textContent = chipDisplayName(key) +
      (key === 'esp32c5' ? '（实验性 · 暂未开放镜像）' : '（暂无固件镜像）');
    sel.appendChild(opt);
  }
  // 手动选择保持; 自动识别模式回到占位
  sel.value = (state.chip && state.chipManual) ? state.chip : '';
}

function chipDisplayName(key) {
  return key === 'esp32' ? 'ESP32' : 'ESP32-' + key.slice(5).toUpperCase();
}

// 手动选择开发板型号 (串口识别成功前可预选; 识别成功后自动匹配仍优先)
$('chipLabel').onchange = () => {
  const v = $('chipLabel').value;
  if (v.startsWith('exp:')) { $('chipLabel').value = ''; return; }
  if (!v) {
    state.chip = null; state.chipManual = false; state.bin = null; state.binStr = null;
  } else {
    if (state.chip && state.chip !== v && state.esploader) {
      terminalAppend(`${nowTs()} [chip] 远端设备已连接, 手动切换型号可能烧错镜像 — 建议先断开再切换\n`);
    }
    state.chip = v; state.chipManual = true; state.bin = null; state.binStr = null;
    terminalAppend(`${nowTs()} [chip] 已手动指定开发板型号: ${chipDisplayName(v)}\n`);
  }
  updateChipUI();
  refreshFlashButton();
};

// 芯片别名: main() 返回 "ESP32-S3 (revision v0.2)" / "ESP32 (revision v3.1)" 等
function chipKeyFromDescription(desc) {
  const m = /ESP32-(\w+)/.exec(desc);
  if (m) {
    const key = 'esp32' + m[1].toLowerCase();
    return state.manifest.supported.includes(key) ? key : null;
  }
  if (desc.startsWith('ESP32')) return state.manifest.supported.includes('esp32') ? 'esp32' : null;
  return null;
}

// ---------- 串口连接 ----------
$('btnChoosePort').onclick = async () => {
  if (!window.isSecureContext) {
    alert('Web Serial 需要安全上下文：请通过 http://localhost:8787 或 https 访问本页。');
    return;
  }
  if (!('serial' in navigator)) {
    alert('此浏览器不支持 Web Serial。请使用 Chrome / Edge 最新版 (localhost 访问本页)。');
    return;
  }
  try {
    state.port = await navigator.serial.requestPort({});
    state.port.addEventListener('disconnect', onSerialGone);
    $('portLabel').textContent = '已授权串口 — 已选择设备 —';
    $('btnConnect').disabled = false;
  } catch { /* 用户取消 */ }
};

const onSerialGone = () => {
  setStatus(false, '未连接');
  state.consoleConn = false;
  state.port = state.transport = state.esploader = null;
  $('btnConnect').disabled = false;
  $('btnDisconnect').disabled = true;
  $('portLabel').textContent = '已授权串口 — 无已授权端口 —';
  msg('串口已断开。重新点「连接」可继续 (烧录码仍有效)', 'warn');
};

async function connect() {
  if (!state.port) return null;
  const skipReset = $('skipAutoReset').checked;
  if (skipReset) terminalAppend('[hint] 已选择跳过自动复位: 请按住 BOOT 键, 必要时再按 RESET / 重新插拔进入下载模式\n');
  $('btnConnect').disabled = true;
  try {
    setStatus(true, '连接中… (尝试进入下载模式)');
    state.transport = new Transport(state.port, false);
    state.esploader = new ESPLoader({
      transport: state.transport,
      baudrate: BAUD_FLASH,
      terminal: loaderTerminal,
      debugLogging: false,
    });
    const desc = await state.esploader.main(); // 复位进下载模式 → 读芯片 → 上传 stub
    const detected = chipKeyFromDescription(desc);
    if (detected) {
      if (state.chip && state.chip !== detected && state.chipManual) {
        terminalAppend(`${nowTs()} [chip] 检测到实际芯片 ${desc} — 与手动指定的 ${chipDisplayName(state.chip)} 不符, 已按检测值自动匹配 (防止烧错镜像)\n`);
      }
      state.chip = detected; state.chipManual = false;
    } else if (!state.chip) {
      msg(`识别到芯片 ${desc}, 但服务端没有该芯片的镜像`, 'warn');
    } else {
      terminalAppend(`${nowTs()} [chip] 无法从镜像清单匹配到 ${desc}, 使用手动指定: ${chipDisplayName(state.chip)}\n`);
    }
    updateChipUI();
    setStatus(true, '已连接 · ' + desc);
    $('btnDisconnect').disabled = false;
    return desc;
  } catch (e) {
    terminalAppend('\n[connect] 失败: ' + e.message + '\n');
    setStatus(false, '未连接');
    $('btnConnect').disabled = false;
    state.transport = state.esploader = null;
    if (!$('skipAutoReset').checked) {
      msg('连接失败? 请勾选「跳过自动复位」, 按住 BOOT 再点连接', 'warn');
    } else {
      msg('连接失败: ' + e.message, 'err');
    }
    throw e;
  }
}

$('btnConnect').onclick = () => connect().catch(() => {});

$('btnDisconnect').onclick = async () => {
  try {
    if (state.transport) await state.transport.disconnect();
    await sleep(300);
  } catch { /* ignore */ }
  // 清空 transport/esploader 引用: 否则再次点「开始烧录」会跳过重连, 直接对已断开的 transport 写 flash
  state.transport = state.esploader = null;
  state.consoleConn = false;
  $('btnConnect').disabled = false; $('btnDisconnect').disabled = true;
  setStatus(false, '未连接');
  if (!state.chipManual) { state.chip = null; updateChipUI(); }
};

function updateChipUI() {
  const key = state.chip;
  const sel = $('chipLabel');
  if (!key) {
    sel.value = '';
    $('fwLabel-mini').textContent = '—';
    $('fwSize').textContent = '';
    return;
  }
  sel.value = key;
  const fw = state.manifest.chips[key];
  $('fwLabel-mini').textContent = fw ? 'v' + fw.version : '该芯片暂无镜像';
  $('fwSize').textContent = fw ? `${(fw.size / 1024).toFixed(0)} KB` : '';
}

// ---------- 烧录码 ----------
$('flashCode').addEventListener('input', () => {
  $('flashCode').className = '';
  state.nonce = null; state.code = null;
  $('btnVerify').disabled = $('flashCode').value.trim().length < 6;
  refreshFlashButton(); checkRedeemHint();
});
$('flashCode').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !$('btnVerify').disabled) {
    $('btnVerify').click();
  }
});

function refreshFlashButton() {
  const ck = $('agreeTerms').checked;
  const haveNonce = !!state.nonce;
  // 型号就绪 = 已选定且该芯片有镜像 (手动预选或自动识别均可)
  const haveFw = !!(state.chip && state.manifest.chips[state.chip]);
  const noPort = !state.port;
  // 都满足才可点; 未连接时也允许点 (点了会先走连接流程)
  $('btnFlash').disabled = !(ck && haveNonce && (haveFw || noPort));
}

function checkRedeemHint() {
  if (state.code && !state.nonce) msg('校验已过期或失败, 请重新校验烧录码', 'warn');
}

$('btnVerify').onclick = async () => {
  const code = $('flashCode').value.trim().toUpperCase();
  // 非手动指定的型号随轮次重置; 手动指定的保留 (用户明确意图)
  if (!state.chipManual) state.chip = null;
  state.bin = null; state.binStr = null;
  updateChipUI();
  // verify 时可先不带芯片
  try {
    $('btnVerify').disabled = true;
    const r = await fetch('/api/codes/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    const j = await r.json();
    if (!r.ok || !j.ok) { msg(j.error || '校验失败', 'err'); $('flashCode').className = 'err'; refreshFlashButton(); return; }
    state.code = code; state.nonce = j.nonce;
    $('flashCode').className = 'ok';
    msg('✓ 校验通过 (15 分钟内有效), 可点「开始烧录」', 'ok');
    refreshFlashButton();
  } catch (e) {
    msg('校验请求失败: ' + e.message, 'err');
  } finally { $('btnVerify').disabled = false; }
};

$('agreeTerms').onchange = refreshFlashButton;

// fetch 镜像 + 本地完整性校验: manifest.md5 是注册镜像时写入 DB 的可信摘要,
// 下载后必须与之比对, 防止镜像被替换/传输损坏后仍被烧进设备。
async function loadFwBinary(key) {
  const fw = state.manifest.chips[key];
  const r = await fetch(`/api/firmware/bin/${key}`);
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.error || `镜像加载失败 (${r.status})`);
  }
  const ab = await r.arrayBuffer();
  const u8 = new Uint8Array(ab);
  // latin1 串只用于 CryptoJS 计算 MD5; esptool-js 0.7.x 的 writeFlash 直接收 Uint8Array
  const bstr = u8ToLatin1(u8);
  const expected = String(fw?.md5 || '').toLowerCase();
  if (expected) {
    if (typeof CryptoJS === 'undefined') {
      throw new Error('镜像完整性校验不可用: CryptoJS 未加载 (请检查网络后刷新页面)');
    }
    const actual = CryptoJS.MD5(CryptoJS.enc.Latin1.parse(bstr)).toString().toLowerCase();
    if (actual !== expected) {
      throw new Error(`镜像 MD5 不一致 (manifest=${expected}, 实际=${actual}); 文件可能损坏或被替换, 已阻止烧录`);
    }
    if (fw.size && u8.length !== fw.size) {
      throw new Error(`镜像大小不一致 (manifest=${fw.size}, 实际=${u8.length}), 已阻止烧录`);
    }
    terminalAppend(`${nowTs()} [fw] 完整性校验通过: md5=${actual}, ${u8.length} bytes\n`);
  } else {
    terminalAppend(`${nowTs()} [fw] 警告: manifest 未提供 md5, 跳过完整性校验\n`);
  }
  state.bin = u8;
  state.binStr = bstr;
  state.binMd5 = fw?.md5 || null;
  state.flashVersion = fw?.version || null;
}

// ---------- 烧录主流程 ----------
$('btnFlash').onclick = async () => {
  if (!$('agreeTerms').checked) return;
  if (!state.nonce) { msg('请先校验烧录码', 'warn'); return; }
  if (state.backingUp) { msg('正在备份 Flash, 请等备份完成后再烧录', 'warn'); return; }
  const nonce = state.nonce; // 本轮使用, 无论成败轮次结束都作废
  state.nonce = null;
  state.flashing = true;
  refreshFlashButton();

  try {
    // 1. 串口就绪 + 芯片识别 (若尚未连接, 或还停在 115200 控制台模式, 先回到下载模式)
    if (!state.esploader || state.consoleConn) {
      setStatus(true, '连接中…');
      try { await enterDownloadMode(); } catch (e) { throw new Error('串口连接失败: ' + e.message); }
    }
    const chipKey = state.chip;
    if (!chipKey) throw new Error('无法识别芯片, 或服务端没有该芯片的镜像');
    const fw = state.manifest.chips[chipKey];
    if (!fw) throw new Error(`芯片 ${chipKey} 暂无镜像, 请先编译并注册固件`);

    // 2. 下载镜像
    progress(2, '下载镜像…');
    await loadFwBinary(chipKey);

    // 3. 写入 (单镜像 offset 0x0)
    $('btnFlash').disabled = true;
    progress(5, '烧录开始…');
    // esptool-js 0.7.x: fileArray.data 必须是 Uint8Array (0.5.x 的 latin1 字符串入参已废弃)
    const image = state.bin;

    await state.esploader.writeFlash({
      fileArray: [{ data: image, address: 0 }],
      flashSize: 'keep',
      flashMode: 'keep',
      flashFreq: 'keep',
      eraseAll: false,
      compress: true,
      reportProgress: (_fi, written, total) => {
        const pct = 5 + (written / total) * 88;
        const kbs = (written / 1024).toFixed(0) + ' KB';
        const pctNum = Math.round((written / total) * 100);
        progress(pct, `烧录中 ${pctNum}% · ${kbs}`);
      },
      calculateMD5Hash: (img) => CryptoJS.MD5(CryptoJS.enc.Latin1.parse(u8ToLatin1(img))).toString(),
    });

    // 4. 成功 → 核销 → 提示
    progress(100, '✓ 烧录成功, 设备复位运行中');
    terminalAppend('\n[flash] 烧录成功! 设备即将出热点 WiFi-xxxx (密码 00000000), 后台 http://192.168.4.1/admin.html\n');
    msg('✓ 烧录成功! 设备已复位, 烧录码已核销。连接热点 WiFi-xxxx, 密码 00000000', 'ok');
    reportRedeem(nonce, true);

    // 5. 稍后切回 115200 挂控制台读启动日志
    setTimeout(() => { startConsole().catch(() => {}); }, 1500);
  } catch (e) {
    terminalAppend('\n[flash] 失败: ' + (e.message || e) + '\n');
    progress(0, '✗ 烧录失败 (烧录码未核销, 可重试)');
    msg('✗ 烧录失败: ' + (e.message || e) + '。烧录码未核销, 请重新校验烧录码再试。', 'err');
    reportRedeem(nonce, false);
  } finally {
    state.flashing = false;
  }
};

async function reportRedeem(nonce, success) {
  if (!nonce) return;
  try {
    const r = await fetch('/api/codes/redeem', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nonce, chip: state.chip, md5: state.binMd5, success }),
    });
    const j = await r.json();
    if (success && j.consumed) terminalAppend('[server] ' + (j.message || '烧录码已核销') + '\n');
    else if (!success) terminalAppend('[server] ' + (j.message || '已上报失败, 码未核销') + '\n');
    if (j.error) terminalAppend('[server] ' + j.error + '\n');
  } catch (e) {
    terminalAppend('[server] 上报失败: ' + e.message + '\n');
  }
}

// ---------- 一键备份整片 Flash ----------
// 备份是只读操作, 不消耗烧录码; 但 readFlash 走 flasher stub, 必须先进入下载模式。
const BACKUP_CHUNK = 0x100000; // 1MB/次: 分段读可避免 esptool-js 内部把 16MB 反复拼接的拷贝开销

function backupSetProgress(read, total, label) {
  const pct = total ? Math.min(100, (read / total) * 100) : 0;
  $('backupBar').style.width = pct.toFixed(1) + '%';
  $('backupLabel').textContent = label ||
    `读取中 ${Math.round(pct)}% · ${(read / 0x100000).toFixed(1)} / ${(total / 0x100000).toFixed(1)} MB`;
}

// 备份需要 stub 下载模式: 先停掉控制台读取循环, 再重建 transport 与 loader
async function enterDownloadMode() {
  if (state.consoleConn) {
    state.consoleConn = false;
    await sleep(300);
  }
  if (state.transport) {
    try { await state.transport.disconnect(); } catch { /* ignore */ }
    state.transport = state.esploader = null;
    await sleep(200);
  }
  if (!state.port) throw new Error('请先在「① 串口连接」选择并授权串口');
  await connect();
}

$('btnBackup').onclick = async () => {
  if (state.backingUp) return;
  if (state.flashing) { msg('正在烧录, 请等烧录完成后再备份', 'warn'); return; }
  if (!('serial' in navigator)) {
    alert('此浏览器不支持 Web Serial。请使用 Chrome / Edge 最新版 (localhost 访问本页)。');
    return;
  }
  state.backingUp = true;
  $('btnBackup').disabled = true;
  backupSetProgress(0, 0, '准备中…');
  let done = false;
  try {
    if (!state.esploader || state.consoleConn) {
      msg('备份需进入下载模式, 正在连接…', '');
      await enterDownloadMode();
    }

    // 容量以 Flash ID 实测为准: 4MB 镜像的板子也可能是 16MB Flash, 必须读满整片才能恢复
    const sizeStr = await state.esploader.detectFlashSize();
    if (!sizeStr) throw new Error('无法读取 Flash ID, 识别不到容量 (请检查供电/连接, 或改用命令行 read-flash)');
    const size = state.esploader.flashSizeBytes(sizeStr);
    if (!(size > 0)) throw new Error(`无法解析 Flash 容量: ${sizeStr}`);
    terminalAppend(`\n${nowTs()} [backup] Flash 容量 ${sizeStr} (${size} bytes), 开始整片读取 (请勿拔线)…\n`);

    // 分块读进预分配的整片缓冲, 同时增量计算 MD5 (避免整片 16MB 再转一份字符串)
    const out = new Uint8Array(size);
    const hasher = typeof CryptoJS !== 'undefined' ? CryptoJS.algo.MD5.create() : null;
    for (let off = 0; off < size; off += BACKUP_CHUNK) {
      const n = Math.min(BACKUP_CHUNK, size - off);
      const chunk = await state.esploader.readFlash(off, n, (_pkt, read) => {
        backupSetProgress(off + Math.min(read, n), size);
      });
      if (!chunk || chunk.length < n) {
        throw new Error(`读取不完整 (0x${off.toString(16)} 处期望 ${n} 字节, 实收 ${chunk ? chunk.length : 0})`);
      }
      const part = chunk.subarray(0, n); // stub 可能多回几个字节, 只取本段
      out.set(part, off);
      if (hasher) hasher.update(CryptoJS.enc.Latin1.parse(u8ToLatin1(part)));
      backupSetProgress(off + n, size);
    }

    // 落盘: 文件名带芯片与时间, 便于区分多块板子的备份
    const d = new Date();
    const stamp = `${d.getFullYear()}${two(d.getMonth() + 1)}${two(d.getDate())}-${two(d.getHours())}${two(d.getMinutes())}`;
    const chipName = state.chip || 'esp32';
    const filename = `${chipName}_backup_${sizeStr.toLowerCase()}_${stamp}.bin`;
    const md5 = hasher ? hasher.finalize().toString() : '(未计算)';
    const url = URL.createObjectURL(new Blob([out], { type: 'application/octet-stream' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    done = true;

    backupSetProgress(size, size, `✓ 备份完成 · ${filename}`);
    terminalAppend(`${nowTs()} [backup] 完成: ${filename} (${size} bytes, md5=${md5})\n`);
    terminalAppend(`${nowTs()} [backup] 请妥善保存; 刷坏后可用 esptool write-flash 0x0 <备份文件> 恢复\n`);
    msg(`✓ 备份完成并已开始下载: ${filename} (${sizeStr})`, 'ok');
  } catch (e) {
    backupSetProgress(0, 0, '✗ 备份失败');
    terminalAppend(`\n[backup] 失败: ${e.message || e}\n`);
    terminalAppend(`${nowTs()} [backup] 设备仍停在下载模式: 重新上电 / 拔插 USB 即可恢复运行\n`);
    msg('✗ 备份失败: ' + (e.message || e) + ' (备份为只读操作, 不影响设备现有固件)', 'err');
  } finally {
    state.backingUp = false;
    $('btnBackup').disabled = false;
    // 备份后芯片仍在 stub: 复位运行原固件, 并切回 115200 控制台
    if (done) {
      try { await state.esploader.after('hard_reset'); } catch { /* ignore */ }
      setTimeout(() => { startConsole().catch(() => {}); }, 800);
    }
  }
};

// ---------- 多系统 / 外部固件刷写 (可刷 Muse / ESPsoup) ----------
let customBinData = null;
let customBinName = '';
let customBinMd5 = '';

function customFlashProgress(pct, label) {
  const bar = $('customFlashBar');
  const txt = $('customFlashLabel');
  if (bar) bar.style.width = Math.min(100, Math.max(0, pct)) + '%';
  if (txt) txt.textContent = label;
}

const customFileInput = $('customFileInput');
const btnChooseCustomFile = $('btnChooseCustomFile');
const btnCustomFlash = $('btnCustomFlash');

if (btnChooseCustomFile && customFileInput) {
  btnChooseCustomFile.onclick = () => customFileInput.click();
  customFileInput.onchange = (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    customBinName = file.name;
    const reader = new FileReader();
    reader.onload = () => {
      customBinData = new Uint8Array(reader.result);
      customBinMd5 = typeof CryptoJS !== 'undefined'
        ? CryptoJS.MD5(CryptoJS.enc.Latin1.parse(u8ToLatin1(customBinData))).toString()
        : '';
      const sizeMb = (customBinData.length / 1024 / 1024).toFixed(2);
      $('customFileName').textContent = `${file.name} (${sizeMb} MB, MD5: ${customBinMd5.slice(0, 8)}…)`;
      if (btnCustomFlash) btnCustomFlash.disabled = false;
      terminalAppend(`${nowTs()} [custom] 已加载固件: ${file.name} (${customBinData.length} bytes, md5=${customBinMd5})\n`);
    };
    reader.readAsArrayBuffer(file);
  };
}

if (btnCustomFlash) {
  btnCustomFlash.onclick = async () => {
    if (!customBinData || customBinData.length === 0) {
      msg('请先选择本地 .bin 固件文件', 'warn');
      return;
    }
    if (state.flashing || state.backingUp) {
      msg('设备正忙, 请稍后再试', 'warn');
      return;
    }
    const slotSelect = $('customSlotSelect');
    const targetAddr = parseInt(slotSelect ? slotSelect.value : '0x7F0000', 16);
    const slotText = slotSelect ? slotSelect.options[slotSelect.selectedIndex].text : `0x${targetAddr.toString(16)}`;

    if (!confirm(`确定将固件【${customBinName}】写入【${slotText}】？\n\n- 写入对应系统分区不会影响其他分区已有数据。\n- 写入完成后可在 Web 后台一键切换或自动重启。`)) {
      return;
    }

    state.flashing = true;
    btnCustomFlash.disabled = true;
    customFlashProgress(5, '准备中…');
    try {
      if (!state.esploader || state.consoleConn) {
        msg('正在连接并进入下载模式…', '');
        await enterDownloadMode();
      }

      terminalAppend(`\n${nowTs()} [custom] 开始写入: ${customBinName} -> 0x${targetAddr.toString(16).toUpperCase()} (${customBinData.length} bytes)\n`);
      customFlashProgress(10, '正在写入 Flash…');

      await state.esploader.writeFlash({
        fileArray: [{ data: customBinData, address: targetAddr }],
        flashSize: 'keep',
        flashMode: 'keep',
        flashFreq: 'keep',
        eraseAll: false,
        compress: true,
        reportProgress: (_fi, written, total) => {
          const pct = Math.round((written / total) * 100);
          const kbs = (written / 1024).toFixed(0) + ' KB';
          customFlashProgress(pct, `写入中 ${pct}% · ${kbs}`);
        },
        calculateMD5Hash: (img) => CryptoJS.MD5(CryptoJS.enc.Latin1.parse(u8ToLatin1(img))).toString(),
      });

      customFlashProgress(100, `✓ 写入成功 · 已刷入 ${slotText}`);
      terminalAppend(`${nowTs()} [custom] 固件写入成功! 目标地址: 0x${targetAddr.toString(16).toUpperCase()}\n`);
      msg(`✓ 固件写入成功! 已刷入 ${slotText}`, 'ok');

      setTimeout(() => { startConsole().catch(() => {}); }, 1500);
    } catch (e) {
      customFlashProgress(0, '✗ 写入失败');
      terminalAppend(`\n[custom] 写入失败: ${e.message || e}\n`);
      msg('✗ 写入失败: ' + (e.message || e), 'err');
    } finally {
      state.flashing = false;
      btnCustomFlash.disabled = false;
    }
  };
}

// ---------- 串口控制台 ----------
async function startConsole() {
  if (!state.transport || state.consoleConn) return;
  try {
    await state.transport.disconnect();
  } catch { /* ignore */ }
  await sleep(200);
  try {
    await state.transport.connect(BAUD_CONSOLE);
  } catch (e) {
    terminalAppend('[console] 无法切到控制台模式: ' + e.message + '\n');
    return;
  }
  state.consoleConn = true;
  const hintEl = $('consoleHint');
  if (hintEl) hintEl.textContent = '控制台读取中 (115200)… 文本日志 + NDJSON 遥测（{ 开头为 JSON 事件）';
  // 经典复位: DTR/RTS 令芯片重启
  try {
    await state.transport.setDTR(false);
    await state.transport.setRTS(true);
    await sleep(120);
    await state.transport.setRTS(false);
  } catch { /* ignore */ }
  try {
    // esptool-js 0.7.x: rawRead(onData, isClosed) 是回调式, 不再返回 async generator
    const dec = new TextDecoder();
    await state.transport.rawRead(
      (data) => terminalAppend(typeof data === 'string' ? data : dec.decode(data, { stream: true })),
      () => !state.consoleConn,
    );
  } catch { /* port closed */ }
  finally {
    state.consoleConn = false;
    if (hintEl) hintEl.textContent = '控制台就绪 · 115200 输出文本日志 + NDJSON 遥测（以 { 开头的行为 JSON 事件）';
  }
}

$('btnResetConsole').onclick = async () => {
  if (!state.transport) return;
  state.consoleConn = false;
  await sleep(100);
  startConsole().catch(() => {});
};

$('btnClear').onclick = () => { $('console').textContent = ''; };

$('btnCopy').onclick = async () => {
  await navigator.clipboard.writeText($('console').textContent);
  $('btnCopy').textContent = '已复制';
  setTimeout(() => ($('btnCopy').textContent = '复制'), 1200);
};

// ---------- 启动 ----------
if (localStorage.getItem('theme') === 'dark') document.documentElement.classList.add('dark');
$('btnTheme').onclick = () => {
  const dark = document.documentElement.classList.toggle('dark');
  localStorage.setItem('theme', dark ? 'dark' : 'light');
  $('btnTheme').textContent = dark ? '🌙' : '☀️';
};
if (document.documentElement.classList.contains('dark')) $('btnTheme').textContent = '🌙';
$('btnLang').onclick = () => {
  msg('多语言支持规划中，当前默认提供完整简体中文界面', 'hint');
};

bootBanner();
setStatus(false, '未连接');
loadManifest();
